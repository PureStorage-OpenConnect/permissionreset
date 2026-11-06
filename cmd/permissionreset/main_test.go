package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags/cmdflagstest"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	runpkg "github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/signals"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/summary"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// TARGET canonicalization
// ---------------------------------------------------------------------------

func TestTargetForKernelResolvesLocally(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := targetForKernel(link)
	if err != nil {
		t.Fatalf("targetForKernel(%q): %v", link, err)
	}
	// EvalSymlinks may itself resolve /tmp, so compare against the same treatment
	// of the answer rather than against the raw path.
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("targetForKernel(%q) = %q, want %q: the kernel branch must still resolve local symlinks", link, got, want)
	}
}

func TestTargetForKernelRejectsWhatItAlwaysRejected(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := targetForKernel(filepath.Join(tmp, "missing")); err == nil {
		t.Error("a nonexistent local path must be rejected")
	} else if !strings.Contains(err.Error(), "resolve target") {
		t.Errorf("err = %v, want it to keep the historical \"resolve target\" wording", err)
	}

	if _, err := targetForKernel(file); err == nil {
		t.Error("a regular file must be rejected")
	} else if !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("err = %v, want it to keep the historical \"is not a directory\" wording", err)
	}

	if _, err := targetForKernel("/"); err == nil {
		t.Error("the filesystem root must be rejected on the kernel transport")
	} else if !strings.Contains(err.Error(), "refusing to operate on filesystem root /") {
		t.Errorf("err = %v, want the filesystem-root refusal", err)
	}
}

// TestTargetForUserspaceTouchesNoLocalFilesystem is the blocker. A server-side
// path must survive canonicalization byte for byte: unchanged when nothing local
// exists at it, and -- the wrong-object case -- unchanged when a local tree
// does, including through a local symlink that EvalSymlinks would have followed.
func TestTargetForUserspaceTouchesNoLocalFilesystem(t *testing.T) {
	// A path that exists on no local filesystem, which is the normal case: the
	// export is on the array and this host has no mount for it.
	got, err := targetForUserspace("/fb-perms/data", "/fb-perms")
	if err != nil {
		t.Fatalf("a server-side path must not need to exist locally: %v", err)
	}
	if got != "/fb-perms/data" {
		t.Errorf("target = %q, want %q", got, "/fb-perms/data")
	}

	// The second-order failure: a local tree DOES exist at the typed path, and
	// one of its components is a symlink. Resolving it would address a different
	// server-side object than the one typed.
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	if err := os.MkdirAll(filepath.Join(real, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	typed := filepath.Join(link, "data")

	got, err = targetForUserspace(typed, tmp)
	if err != nil {
		t.Fatalf("targetForUserspace(%q): %v", typed, err)
	}
	if got != typed {
		t.Errorf("target = %q, want %q unchanged: canonicalization followed a LOCAL symlink for a server-side path, which addresses a different object than the one typed", got, typed)
	}
}

func TestTargetForUserspaceCleansLexically(t *testing.T) {
	got, err := targetForUserspace("/export//sub/../sub/./data/", "/export")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/export/sub/data" {
		t.Errorf("target = %q, want %q: nfs41 compares the target against the export lexically, so it must arrive cleaned", got, "/export/sub/data")
	}
}

func TestTargetForUserspaceRequiresAnAbsoluteTarget(t *testing.T) {
	if _, err := targetForUserspace("data", "/export"); err == nil {
		t.Fatal("a relative TARGET must be rejected: the only thing that could make it absolute is the LOCAL working directory, which names nothing on the server")
	}
	if _, err := targetForUserspace("./data", "/export"); err == nil {
		t.Fatal("a relative TARGET must be rejected even when it is spelled with a leading dot")
	}
}

func TestTargetForUserspaceAllowsTheExportRoot(t *testing.T) {
	for _, tc := range []struct{ target, export string }{
		{"/fb-perms", "/fb-perms"},
		{"/fb-perms/", "/fb-perms"},
		{"/", "/export"}, // outside the export; nfs41 rejects it, not this function
	} {
		got, err := targetForUserspace(tc.target, tc.export)
		if err != nil {
			t.Errorf("targetForUserspace(%q, %q) = %v; a target at the export root is the ordinary case", tc.target, tc.export, err)
			continue
		}
		if want := filepath.Clean(tc.target); got != want {
			t.Errorf("targetForUserspace(%q, %q) = %q, want %q", tc.target, tc.export, got, want)
		}
	}
}

func TestTargetForUserspaceRefusesTheWholeServerRoot(t *testing.T) {
	if _, err := targetForUserspace("/", "/"); err == nil {
		t.Fatal("TARGET / under --export / is the whole-server case and must be refused")
	}
	if _, err := targetForUserspace("//", "/"); err == nil {
		t.Fatal("the refusal must be made after cleaning, not before")
	}
}

// ---------------------------------------------------------------------------
// The gate refusal as it reaches a terminal
// ---------------------------------------------------------------------------

const wantRefusal = "error: --transport=userspace requires a FlashBlade; refusing to continue"

func TestRefusalRendersWithTheLowercasePrefix(t *testing.T) {
	got := transportError(nfs41.ErrNotPureServer)
	if got != wantRefusal {
		t.Errorf("transportError = %q, want exactly %q", got, wantRefusal)
	}
	if strings.HasPrefix(got, "ERROR:") {
		t.Error("the refusal must not render through the generic uppercase ERROR handler")
	}
}

// TestRenderedRefusalDisclosesNothing is the security property at the point where
// it is actually observable: the terminal. A wrapper that named the observed or
// expected max file size must not be able to reach a user through %v.
func TestRenderedRefusalDisclosesNothing(t *testing.T) {
	wrapped := fmt.Errorf("nfs41: server gate (observed 2199023255552, expected 70368744177664): %w", nfs41.ErrNotPureServer)
	got := transportError(wrapped)
	if got != wantRefusal {
		t.Fatalf("transportError = %q, want exactly %q: the rendered text must come from the sentinel, which cannot grow a value, not from the error chain", got, wantRefusal)
	}
	for _, leak := range []string{"70368744177664", "2199023255552", "max file size", "maxfilesize", "expected"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(leak)) {
			t.Errorf("rendered refusal leaks %q: %q", leak, got)
		}
	}
}

func TestOrdinaryTransportErrorsKeepTheirWording(t *testing.T) {
	if got, want := transportError(errors.New("dial tcp: refused")), "ERROR: dial tcp: refused"; got != want {
		t.Errorf("transportError = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// End to end, against a built binary
// ---------------------------------------------------------------------------

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// permissionresetBinary builds the command once per test binary. run() reads package
// globals and flag.CommandLine, so it cannot be called twice in one process; a
// subprocess is what makes the flag surface, the exit code, and the exact stderr
// text observable together.
// requireKernelTransport skips a test that runs the built binary against a
// local tmpdir. That needs the kernel transport, and the binary carries the
// host's real capabilities, which TestMain cannot pin.
func requireKernelTransport(t *testing.T) {
	t.Helper()
	if !platform.Current().KernelTransport {
		t.Skipf("the built binary has no kernel transport on %s", runtime.GOOS)
	}
}

func permissionresetBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			buildErr = fmt.Errorf("no go tool available: %w", err)
			return
		}
		dir, err := os.MkdirTemp("", "permissionreset-bin")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "permissionreset")
		cmd := exec.Command(goTool, "build", "-o", out, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %v: %s", err, b)
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("building permissionreset: %v", buildErr)
	}
	return binPath
}

type cmdResult struct {
	code   int
	stdout string
	stderr string
}

// binaryTimeout bounds every subprocess this file starts.
//
// It is containment, not impatience. Every invocation below is expected to exit
// in milliseconds because it is refused before any traversal begins -- but the
// thing doing the refusing is the code under test, and one of these invocations
// passes "/" as TARGET. Regress the bare-/ guard in targetForKernel and that
// subprocess starts a dry-run walk of this host's entire root filesystem, which
// measured 110 seconds and 1.2M paths here and is unbounded in general. Nothing
// about the Go test harness contains a subprocess: a t.Fatal or a package-level
// test timeout leaves it running, orphaned, still walking. exec.CommandContext
// kills it, so the regression costs a failed assertion instead of a wedged run.
const binaryTimeout = 60 * time.Second

func runBinary(t *testing.T, dir string, args ...string) cmdResult {
	t.Helper()
	bin := permissionresetBinary(t) // outside the deadline: the first call builds.
	ctx, cancel := context.WithTimeout(context.Background(), binaryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("permissionreset did not exit within %s with args %q: it was still running when the deadline killed it, which for a TARGET this test expects to be refused means the refusal is gone and the process was traversing", binaryTimeout, args)
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running permissionreset: %v", err)
	}
	return cmdResult{code: code, stdout: out.String(), stderr: errb.String()}
}

func specFixture(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "examples", "nfsv4_basic.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("spec fixture: %v", err)
	}
	return abs
}

// TestUserspaceReachesTheClientWithAServerPath is the blocker end to end. The
// path validation must be over before anything transport-specific runs, so a
// server-side path that exists on no local filesystem gets as far as the client.
//
// --server points at a port nothing listens on, but nothing is dialed either:
// nfs41.normalizeConfig runs before the first connection, so the export
// containment check is what answers, offline and deterministically. That answer
// naming the target is what makes the target's value observable at all.
func TestUserspaceReachesTheClientWithAServerPath(t *testing.T) {
	res := runBinary(t, t.TempDir(),
		"--spec", specFixture(t),
		"--transport", "userspace",
		"--server", "127.0.0.1:1",
		"--export", "/export-that-is-not-mounted-here",
		"/some-other-export/data")
	if res.code == 0 {
		t.Fatalf("want a nonzero exit; stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	for _, local := range []string{"resolve target", "is not a directory"} {
		if strings.Contains(res.stderr, local) {
			t.Errorf("stderr mentions %q: TARGET is a server-side path and must not be validated against the local filesystem\nstderr: %s", local, res.stderr)
		}
	}
	if strings.Contains(res.stderr, "no such file or directory") {
		t.Errorf("transport stderr mentions a local missing path: TARGET is a server-side path and must not be validated against the local filesystem\nstderr: %s", res.stderr)
	}
	if !strings.Contains(res.stderr, "outside export") {
		t.Errorf("want the client's own containment refusal, which proves the path reached it; stderr: %s", res.stderr)
	}
}

// TestUserspaceDoesNotRewriteThroughALocalSymlink is the wrong-object case with a
// local tree present. The path the client is told about must be the path typed.
func TestUserspaceDoesNotRewriteThroughALocalSymlink(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "real", "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tmp, "real"), filepath.Join(tmp, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	typed := filepath.Join(tmp, "link", "data")

	res := runBinary(t, tmp,
		"--spec", specFixture(t),
		"--transport", "userspace",
		"--server", "127.0.0.1:1",
		"--export", "/export-that-is-not-mounted-here",
		typed)
	if !strings.Contains(res.stderr, typed) {
		t.Errorf("stderr does not name the path that was typed (%q); the client was told about a different object\nstderr: %s", typed, res.stderr)
	}
	if strings.Contains(res.stderr, filepath.Join(tmp, "real", "data")) {
		t.Errorf("stderr names the symlink-resolved path; TARGET was rewritten through a LOCAL symlink\nstderr: %s", res.stderr)
	}
}

// TestUserspaceRejectsARelativeTarget: the local working directory names nothing
// on the server, so prepending it silently changes which object is addressed.
func TestUserspaceRejectsARelativeTarget(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmp, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := runBinary(t, tmp,
		"--spec", specFixture(t),
		"--transport", "userspace",
		"--server", "127.0.0.1:1",
		"--export", "/export-that-is-not-mounted-here",
		"data")
	if res.code == 0 {
		t.Fatal("a relative TARGET must be refused")
	}
	if !strings.Contains(res.stderr, "absolute") {
		t.Errorf("want an explicit absolute-path refusal; stderr: %s", res.stderr)
	}
	if strings.Contains(res.stderr, filepath.Join(tmp, "data")) {
		t.Errorf("stderr names the local cwd joined to TARGET: filepath.Abs still ran\nstderr: %s", res.stderr)
	}
}

func TestKernelTransportStillValidatesLocally(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	spec := specFixture(t)

	res := runBinary(t, tmp, "--spec", spec, filepath.Join(tmp, "missing"))
	if res.code == 0 || !strings.Contains(res.stderr, "resolve target") {
		t.Errorf("the kernel transport must still reject a nonexistent TARGET; code=%d stderr=%s", res.code, res.stderr)
	}

	res = runBinary(t, tmp, "--spec", spec, "/")
	if res.code == 0 || !strings.Contains(res.stderr, "refusing to operate on filesystem root /") {
		t.Errorf("the kernel transport must still refuse /; code=%d stderr=%s", res.code, res.stderr)
	}
}

func TestHelpExitsSuccessfully(t *testing.T) {
	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"-h"}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, want 0; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "usage: permissionreset") {
		t.Fatalf("stderr = %q, want usage", errOut.String())
	}
}

func TestUnknownFlagExitsTwo(t *testing.T) {
	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, want 2; stderr=%q", code, errOut.String())
	}
}

// TestUnsafeOverrideIsUndocumentedButAccepted is a security property: the flag
// must not advertise itself in --help while remaining usable by someone who
// already knows the consequences.
func TestUnsafeOverrideIsUndocumentedButAccepted(t *testing.T) {
	tmp := t.TempDir()
	help := runBinary(t, tmp, "-h")
	both := help.stdout + help.stderr
	if !strings.Contains(both, "usage: permissionreset") {
		t.Fatalf("-h did not print usage: %q", both)
	}
	if n := strings.Count(both, "unsafe-allow-non-pure-server"); n != 0 {
		t.Errorf("--help mentions the unsafe override %d times, want 0:\n%s", n, both)
	}

	res := runBinary(t, tmp,
		"--spec", specFixture(t),
		"--transport", "userspace",
		"--server", "127.0.0.1:1",
		"--export", "/e",
		"--unsafe-allow-non-pure-server",
		"/e/data")
	if strings.Contains(res.stderr, "flag provided but not defined") {
		t.Errorf("the undocumented flag must still be accepted; stderr: %s", res.stderr)
	}
}

// ---------------------------------------------------------------------------
// --workers default resolution
// ---------------------------------------------------------------------------

// TestWorkersFlagDetectionUsesVisit pins the detection idiom itself against a
// private FlagSet, so it exercises flag.Visit rather than a value comparison.
func TestWorkersFlagDetectionUsesVisit(t *testing.T) {
	typed := func(args ...string) bool {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Int("workers", defaultWorkersFallback, "parallel workers")
		if err := fs.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		seen := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "workers" {
				seen = true
			}
		})
		return seen
	}

	if typed() {
		t.Error("no --workers on the command line must not count as typed")
	}
	if !typed("--workers", "128") {
		t.Error("--workers 128 must count as typed even though it equals the fallback")
	}
	if !typed("--workers", "1024") {
		t.Error("--workers 1024 must count as typed")
	}
}

func TestTuningMatchIsAnnouncedAndExplicitFlagWins(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)

	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections:       32,
		Slots:             64,
		Workers:           64,
		BatchSize:         100,
		MaxOpsPerCompound: 8,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), "--connections=16", "--workers=128", target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if captured.Connections != 16 || captured.Workers != 128 || captured.BatchSize != 100 || captured.Slots != 64 || captured.MaxOpsPerCompound != 8 {
		t.Fatalf("Run config = %+v, want explicit connections/workers and remaining tuned values", *captured)
	}
	want := fmt.Sprintf("tuning: %s@192.0.2.1:/data/kernel from %s confidence=low (connections=16[flag, file 32] slots=64 workers=128[flag, file 64] batch-size=100 max-ops-per-compound=8)\n", hostName(t), tuning.PathForExecutable(executable))
	if got := errOut.String(); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

// TestTuningAnnouncementMarksATypedFlagThatMatchesTheFile pins the case the
// difference-only rule would miss. The line's defect was attribution, not
// disagreement: it named the tuning file and then printed values a flag had
// supplied. A flag that happens to type the same number the file holds still
// did not come from the file, so it is marked too -- otherwise an operator
// reading the line cannot tell which of two identical numbers they are
// responsible for.
func TestTuningAnnouncementMarksATypedFlagThatMatchesTheFile(t *testing.T) {
	captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)

	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections:       32,
		Slots:             64,
		Workers:           128,
		BatchSize:         100,
		MaxOpsPerCompound: 8,
	})

	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--spec", specFixture(t), "--workers=128", target}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if got := errOut.String(); !strings.Contains(got, "workers=128[flag, file 128]") {
		t.Fatalf("stderr = %q, want workers marked as flag-supplied even though it equals the file value", got)
	}
}

// TestTuningAnnouncementLeavesUntypedValuesUnmarked is the other half: a value
// the file really did supply must carry no marker, or the marker stops meaning
// anything.
func TestTuningAnnouncementLeavesUntypedValuesUnmarked(t *testing.T) {
	captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)

	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections:       32,
		Slots:             64,
		Workers:           1024,
		BatchSize:         100,
		MaxOpsPerCompound: 8,
	})

	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if got := errOut.String(); strings.Contains(got, "[flag,") {
		t.Fatalf("stderr = %q, want no flag markers when no tuning flag was typed", got)
	}
}

// TestTuningAnnouncementNamesAnUnrecordedConfidence pins the missing case. An
// entry written by an older sweeper, or hand-edited, has no confidence at all,
// and an empty string there would read as a field the announcement forgot.
func TestTuningAnnouncementNamesAnUnrecordedConfidence(t *testing.T) {
	captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeTuningEntries(t, executable, tuning.Entry{
		Clients:   []string{hostName(t)},
		Server:    "192.0.2.1",
		Export:    "/data",
		Transport: "kernel",
		Params:    tuning.Params{Workers: 64, BatchSize: 100},
	})

	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if got := errOut.String(); !strings.Contains(got, "confidence=unknown") {
		t.Fatalf("stderr = %q, want it to report confidence=unknown", got)
	}
}

func TestUserspaceTuningMatchUsesExplicitServerAndExport(t *testing.T) {
	captured := captureRunConfig(t)
	executable := configureExecutablePath(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "userspace", tuning.Params{
		Connections:       32,
		Slots:             64,
		Workers:           1024,
		BatchSize:         100,
		MaxOpsPerCompound: 8,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data/subdir",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if captured.Transport != "userspace" || captured.Server != "192.0.2.1" || captured.Export != "/data" || captured.Root != "/data/subdir" {
		t.Fatalf("Run config target = %+v, want userspace 192.0.2.1:/data/subdir", *captured)
	}
	if captured.Connections != 32 || captured.Slots != 64 || captured.Workers != 1024 || captured.BatchSize != 100 || captured.MaxOpsPerCompound != 8 {
		t.Fatalf("Run config tuning = %+v", *captured)
	}
	if want := fmt.Sprintf("tuning: %s@192.0.2.1:/data/userspace from %s", hostName(t), tuning.PathForExecutable(executable)); !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr = %q, want %q", errOut.String(), want)
	}
}

func TestNoMatchingTuningEntryIsSilent(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)

	writeMatchingTuning(t, executable, "192.0.2.2", "/data", "kernel", tuning.Params{Workers: 64})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want no announcement or warning", errOut.String())
	}
	if captured.Workers != 0 {
		t.Fatalf("Workers = %d, want existing untyped-workers sentinel", captured.Workers)
	}
}

func TestMultiClientEntryContainingThisHostDoesNotMatchSoloRun(t *testing.T) {
	captured := captureRunConfig(t)
	executable := configureExecutablePath(t)
	otherClient := "another-client"
	if hostName(t) == otherClient {
		otherClient = "a-different-client"
	}
	writeTuningEntries(t, executable, tuning.Entry{
		Clients:   []string{otherClient, hostName(t)},
		Server:    "192.0.2.1",
		Export:    "/data",
		Transport: "userspace",
		Params: tuning.Params{
			Connections: 32,
			Workers:     64,
			BatchSize:   100,
		},
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	// The dry-run credential note is unconditional on a userspace dry run and is
	// not a tuning announcement; what this test is about is that no entry
	// matched, so strip it before asserting silence.
	if rest := withoutCredentialNote(errOut.String()); rest != "" {
		t.Fatalf("stderr = %q, want no announcement or warning", rest)
	}
	assertBuiltInParams(t, captured)
}

func TestInvalidTuningParamsWarnAndUseBuiltIns(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: 32,
		Workers:     64,
		BatchSize:   0,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning:") || !strings.Contains(errOut.String(), "batch_size absent or zero; entire tuning entry discarded; using built-in defaults") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func TestTunedZeroWorkersWarnsAndUsesBuiltIns(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: 32,
		Workers:     0,
		BatchSize:   100,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning:") || !strings.Contains(errOut.String(), "workers absent or zero; entire tuning entry discarded; using built-in defaults") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

// TestDescriptorBudgetChargesWhatTheTransportOpens pins which parameter is
// charged against RLIMIT_NOFILE on which transport, in both directions on both
// transports — so swapping the two charges fails here rather than passing as a
// pair of unpinned defaults.
//
// userspace charges connections only: a connection is a socket, and userspace
// enumeration reads over that same pool, so a worker holds no descriptor there.
// kernel charges workers only: each in-flight walker holds a readdir descriptor,
// while connections is a field that transport never reads.
//
// The explicit rows pin the other half: a field the operator typed is never
// charged, because precedence already discarded the entry's value for it, and an
// explicit field must not exempt the field that is actually charged.
func TestDescriptorBudgetChargesWhatTheTransportOpens(t *testing.T) {
	oldGetRlimit := getRlimit
	t.Cleanup(func() { getRlimit = oldGetRlimit })

	reserve := tuning.LiveDescriptorReserve()
	// boundary: value + reserve == soft (fits); value + reserve == soft+1 (doesn't)
	boundaryConn := int(1024 - reserve)
	boundaryWorker := int(1024 - reserve)

	tests := []struct {
		name        string
		transport   string
		connections int
		workers     int
		soft        uint64
		getErr      error
		explicit    []string
		wantErr     string
	}{
		{name: "userspace coupon collector value fits 1024", transport: "userspace", connections: 519, workers: 128, soft: 1024},
		{name: "userspace ceiling exceeds 1024", transport: "userspace", connections: 4096, workers: 128, soft: 1024,
			wantErr: "file descriptors but soft RLIMIT_NOFILE is 1024"},
		{name: "userspace ceiling fits high limit", transport: "userspace", connections: 4096, workers: 128, soft: 8192},
		{name: "userspace connections at the boundary", transport: "userspace", connections: boundaryConn, workers: 128, soft: 1024},
		{name: "userspace connections one past the boundary", transport: "userspace", connections: boundaryConn + 1, workers: 128, soft: 1024,
			wantErr: "file descriptors but soft RLIMIT_NOFILE is 1024"},
		// The measured userspace-against-FlashBlade worker count is 1024, which
		// internal/run applies as its own default. Charging it against a soft
		// limit of 1024 would refuse an entry and then run the same number.
		{name: "userspace does not charge the measured worker default", transport: "userspace", connections: 519, workers: 1024, soft: 1024},
		{name: "userspace does not charge workers at all", transport: "userspace", connections: 16, workers: maxTunedWorkers, soft: 1024},

		{name: "kernel does not charge connections", transport: "kernel", connections: 4096, workers: 128, soft: 1024},
		{name: "kernel charges workers", transport: "kernel", connections: 0, workers: 4096, soft: 1024,
			wantErr: "file descriptors but soft RLIMIT_NOFILE is 1024"},
		{name: "kernel workers at the boundary", transport: "kernel", connections: 0, workers: boundaryWorker, soft: 1024},
		{name: "kernel workers one past the boundary", transport: "kernel", connections: 0, workers: boundaryWorker + 1, soft: 1024,
			wantErr: "file descriptors but soft RLIMIT_NOFILE is 1024"},

		{name: "explicit connections is not charged on userspace", transport: "userspace", connections: 4096, workers: 128, soft: 1024,
			explicit: []string{"connections"}},
		{name: "explicit workers does not exempt connections on userspace", transport: "userspace", connections: 4096, workers: 128, soft: 1024,
			explicit: []string{"workers"},
			wantErr:  "file descriptors but soft RLIMIT_NOFILE is 1024"},
		{name: "explicit workers is not charged on kernel", transport: "kernel", connections: 0, workers: 4096, soft: 1024,
			explicit: []string{"workers"}},
		{name: "explicit connections does not exempt workers on kernel", transport: "kernel", connections: 0, workers: 4096, soft: 1024,
			explicit: []string{"connections"},
			wantErr:  "file descriptors but soft RLIMIT_NOFILE is 1024"},

		{name: "userspace rlimit read failure skips the budget", transport: "userspace", connections: 4096, workers: 8192,
			getErr: errors.New("rlimit unavailable")},
		{name: "kernel rlimit read failure skips the budget", transport: "kernel", connections: 4096, workers: 8192,
			getErr: errors.New("rlimit unavailable")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getRlimit = func(resource int, limit *unix.Rlimit) error {
				if resource != unix.RLIMIT_NOFILE {
					t.Fatalf("resource = %d, want RLIMIT_NOFILE", resource)
				}
				limit.Cur = tc.soft
				return tc.getErr
			}
			explicit := make(map[string]bool)
			for _, name := range tc.explicit {
				explicit[name] = true
			}
			params := tuning.Params{Connections: tc.connections, Workers: tc.workers, BatchSize: 50}
			err := validateTuningParams(params, tc.transport, explicit)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateTuningParams() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateTuningParams() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestKernelEntryIsNotDiscardedOverConnections drives the whole command so the
// transport argument at the call site is pinned, not just the validator: a call
// site that passed a constant transport would refuse this entry.
func TestKernelEntryIsNotDiscardedOverConnections(t *testing.T) {
	stubSoftNofile(t, 1024)
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: maxTunedConnections,
		Workers:     128,
		BatchSize:   100,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.HasPrefix(errOut.String(), "tuning:") {
		t.Fatalf("stderr = %q, want the entry applied rather than refused", errOut.String())
	}
	if captured.Workers != 128 || captured.BatchSize != 100 {
		t.Fatalf("Run config = %+v, want the kernel entry's workers and batch size", *captured)
	}
}

// TestKernelEntryIsDiscardedOverWorkers is the other direction: on the kernel
// transport workers is the descriptor consumer, and a value the table cannot
// hold must be refused rather than left to produce a warned incomplete walk.
func TestKernelEntryIsDiscardedOverWorkers(t *testing.T) {
	stubSoftNofile(t, 1024)
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: 16,
		Workers:     4096,
		BatchSize:   100,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning:") ||
		!strings.Contains(errOut.String(), "file descriptors but soft RLIMIT_NOFILE is 1024") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

// TestExplicitWorkersIsNotChargedAgainstTheEntry is the pair to
// TestKernelEntryIsDiscardedOverWorkers: same entry, same 4096, same soft limit,
// differing only in who supplied the number. Typed on the command line it is not
// the entry's fault, so the entry must survive and its batch_size must still be
// applied — an operator who raises workers deliberately should not see the
// tuning file blamed for it, nor lose the rest of a measured entry over it.
func TestExplicitWorkersIsNotChargedAgainstTheEntry(t *testing.T) {
	stubSoftNofile(t, 1024)
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: 16,
		Workers:     4096,
		BatchSize:   100,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), "--workers=4096", target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "WARNING: tuning:") {
		t.Fatalf("stderr blames the entry for an explicit --workers: %q", errOut.String())
	}
	if !strings.HasPrefix(errOut.String(), "tuning:") {
		t.Fatalf("stderr = %q, want the entry applied rather than refused", errOut.String())
	}
	if captured.Workers != 4096 || captured.BatchSize != 100 || captured.Connections != 16 {
		t.Fatalf("Run config = %+v, want explicit workers with the entry's other fields", *captured)
	}
}

// TestUserspaceEntryIsDiscardedOverConnections keeps the connections charge
// alive where it applies. With the kernel exemption in place, a call site that
// passed a constant "kernel" would drop this rejection silently.
func TestUserspaceEntryIsDiscardedOverConnections(t *testing.T) {
	stubSoftNofile(t, 1024)
	captured := captureRunConfig(t)
	executable := configureExecutablePath(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "userspace", tuning.Params{
		Connections: maxTunedConnections,
		Workers:     128,
		BatchSize:   100,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning:") ||
		!strings.Contains(errOut.String(), "file descriptors but soft RLIMIT_NOFILE is 1024") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func stubSoftNofile(t *testing.T, soft uint64) {
	t.Helper()
	oldGetRlimit := getRlimit
	getRlimit = func(_ int, limit *unix.Rlimit) error {
		limit.Cur = soft
		return nil
	}
	t.Cleanup(func() { getRlimit = oldGetRlimit })
}

// TestValidateTuningParamsBoundaries walks every fixed bound at -1, 0, 1, its
// ceiling and one past it, under a soft descriptor limit high enough that the
// transport-dependent budget never fires — so these rows pin the fixed ranges,
// which are the same on both transports, and nothing else.
//
// The zero rows for workers and batch_size assert their message as well as the
// rejection, because zero is owned by the absent-or-zero check that runs before
// the ranges. Without that assertion the row would pass whether the guard that
// caught it was the one it is named for or not.
func TestValidateTuningParamsBoundaries(t *testing.T) {
	stubSoftNofile(t, 1<<20)

	valid := tuning.Params{
		Connections:       16,
		Slots:             8,
		Workers:           128,
		BatchSize:         50,
		MaxOpsPerCompound: 8,
	}
	tests := []struct {
		name    string
		value   int
		set     func(*tuning.Params, int)
		wantErr bool
		want    string
	}{
		{name: "connections -1", value: -1, set: func(p *tuning.Params, v int) { p.Connections = v }, wantErr: true,
			want: "connections must be between 0 and 4096: -1"},
		{name: "connections 0", value: 0, set: func(p *tuning.Params, v int) { p.Connections = v }}, // valid only on kernel; userspace overrides below
		{name: "connections 1", value: 1, set: func(p *tuning.Params, v int) { p.Connections = v }},
		{name: "connections ceiling", value: maxTunedConnections, set: func(p *tuning.Params, v int) { p.Connections = v }},
		{name: "connections past ceiling", value: maxTunedConnections + 1, set: func(p *tuning.Params, v int) { p.Connections = v }, wantErr: true,
			want: "connections must be between 0 and 4096: 4097"},
		{name: "slots -1", value: -1, set: func(p *tuning.Params, v int) { p.Slots = v }, wantErr: true,
			want: "slots must be between 0 and 4294967295: -1"},
		{name: "slots 0", value: 0, set: func(p *tuning.Params, v int) { p.Slots = v }},
		{name: "slots 1", value: 1, set: func(p *tuning.Params, v int) { p.Slots = v }},
		{name: "workers -1", value: -1, set: func(p *tuning.Params, v int) { p.Workers = v }, wantErr: true,
			want: "workers must be between 1 and 8192: -1"},
		{name: "workers 0", value: 0, set: func(p *tuning.Params, v int) { p.Workers = v }, wantErr: true,
			want: "workers absent or zero; entire tuning entry discarded"},
		{name: "workers 1", value: 1, set: func(p *tuning.Params, v int) { p.Workers = v }},
		{name: "workers ceiling", value: maxTunedWorkers, set: func(p *tuning.Params, v int) { p.Workers = v }},
		{name: "workers past ceiling", value: maxTunedWorkers + 1, set: func(p *tuning.Params, v int) { p.Workers = v }, wantErr: true,
			want: "workers must be between 1 and 8192: 8193"},
		{name: "batch-size -1", value: -1, set: func(p *tuning.Params, v int) { p.BatchSize = v }, wantErr: true,
			want: "batch-size must be between 1 and 65536: -1"},
		{name: "batch-size 0", value: 0, set: func(p *tuning.Params, v int) { p.BatchSize = v }, wantErr: true,
			want: "batch_size absent or zero; entire tuning entry discarded"},
		{name: "batch-size 1", value: 1, set: func(p *tuning.Params, v int) { p.BatchSize = v }},
		{name: "batch-size ceiling", value: maxTunedBatchSize, set: func(p *tuning.Params, v int) { p.BatchSize = v }},
		{name: "batch-size past ceiling", value: maxTunedBatchSize + 1, set: func(p *tuning.Params, v int) { p.BatchSize = v }, wantErr: true,
			want: "batch-size must be between 1 and 65536: 65537"},
		{name: "max-ops-per-compound -1", value: -1, set: func(p *tuning.Params, v int) { p.MaxOpsPerCompound = v }, wantErr: true,
			want: "max-ops-per-compound must be between 0 and 4096: -1"},
		{name: "max-ops-per-compound 0", value: 0, set: func(p *tuning.Params, v int) { p.MaxOpsPerCompound = v }},
		{name: "max-ops-per-compound 1", value: 1, set: func(p *tuning.Params, v int) { p.MaxOpsPerCompound = v }},
		{name: "max-ops-per-compound ceiling", value: maxTunedMaxOpsPerCompound, set: func(p *tuning.Params, v int) { p.MaxOpsPerCompound = v }},
		{name: "max-ops-per-compound past ceiling", value: maxTunedMaxOpsPerCompound + 1, set: func(p *tuning.Params, v int) { p.MaxOpsPerCompound = v }, wantErr: true,
			want: "max-ops-per-compound must be between 0 and 4096: 4097"},
	}
	for _, transportName := range []string{"kernel", "userspace"} {
		for _, tc := range tests {
			t.Run(transportName+" "+tc.name, func(t *testing.T) {
				params := valid
				tc.set(&params, tc.value)
				wantErr, want := tc.wantErr, tc.want
				if transportName == "userspace" && tc.name == "connections 0" {
					wantErr = true
					want = "connections absent or zero; entire tuning entry discarded"
				}
				err := validateTuningParams(params, transportName, nil)
				if (err != nil) != wantErr {
					t.Fatalf("validateTuningParams(%+v) error = %v, wantErr %v", params, err, wantErr)
				}
				if want != "" && !strings.Contains(err.Error(), want) {
					t.Fatalf("validateTuningParams(%+v) error = %v, want %q", params, err, want)
				}
			})
		}
	}
}

func TestPartialTuningEntryListsEveryMissingRequiredField(t *testing.T) {
	oldGetRlimit := getRlimit
	getRlimit = func(_ int, _ *unix.Rlimit) error { return errors.New("unused") }
	t.Cleanup(func() { getRlimit = oldGetRlimit })
	params := tuning.Params{Connections: 32}
	err := validateTuningParams(params, "userspace", nil)
	if err == nil || !strings.Contains(err.Error(), "workers and batch_size absent or zero; entire tuning entry discarded") {
		t.Fatalf("validateTuningParams() error = %v", err)
	}
}

func TestExplicitFlagCanMaskInvalidTunedValue(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections: 32,
		Workers:     64,
		BatchSize:   0,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), "--batch-size=50", target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if captured.Connections != 32 || captured.Workers != 64 || captured.BatchSize != 50 {
		t.Fatalf("Run config = %+v, want explicit batch-size and other tuned values", *captured)
	}
	if !strings.HasPrefix(errOut.String(), "tuning:") {
		t.Fatalf("stderr = %q, want match announcement", errOut.String())
	}
}

func TestExplicitWorkerAndBatchBounds(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		wantCode int
		wantErr  string
	}{
		{name: "workers minimum", flag: "--workers=1", wantCode: 0},
		{name: "workers below minimum", flag: "--workers=0", wantCode: 1, wantErr: "ERROR: --workers must be >= 1 (got 0)"},
		{name: "workers maximum", flag: "--workers=8192", wantCode: 0},
		{name: "workers above maximum", flag: "--workers=8193", wantCode: 1, wantErr: "ERROR: --workers must be <= 8192 (got 8193)"},
		{name: "batch minimum", flag: "--batch-size=1", wantCode: 0},
		{name: "batch below minimum", flag: "--batch-size=0", wantCode: 1, wantErr: "ERROR: --batch-size must be between 1 and 65536 (got 0)"},
		{name: "batch maximum", flag: "--batch-size=65536", wantCode: 0},
		{name: "batch above maximum", flag: "--batch-size=65537", wantCode: 1, wantErr: "ERROR: --batch-size must be between 1 and 65536 (got 65537)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			captureRunConfig(t)
			configureExecutablePath(t)
			var out, errOut strings.Builder
			code := runWithFlagSet([]string{"--spec", specFixture(t), tc.flag, t.TempDir()}, &out, &errOut)
			if code != tc.wantCode {
				t.Fatalf("code=%d, want %d; stderr=%s", code, tc.wantCode, errOut.String())
			}
			if tc.wantErr != "" && !strings.Contains(errOut.String(), tc.wantErr) {
				t.Fatalf("stderr = %q, want %q", errOut.String(), tc.wantErr)
			}
		})
	}
}

func TestExplicitInvalidWorkerIsRejectedWithoutBlamingTuning(t *testing.T) {
	executable, target := configureKernelTuningTest(t)
	writeMatchingTuning(t, executable, "192.0.2.1", "/data", "kernel", tuning.Params{
		Connections:       32,
		Slots:             64,
		Workers:           64,
		BatchSize:         100,
		MaxOpsPerCompound: 8,
	})

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), "--workers=0", target}, &out, &errOut)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "WARNING: tuning:") {
		t.Fatalf("stderr blames the tuning entry for an explicit invalid flag: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "ERROR: --workers must be >= 1 (got 0)") {
		t.Fatalf("stderr = %q, want explicit workers rejection", errOut.String())
	}
}

func TestKernelTargetWithoutNFSMountIsSilent(t *testing.T) {
	captured := captureRunConfig(t)
	executable := configureExecutablePath(t)
	writeSiblingTuning(t, executable, "version: 1\ntunings: []\n")
	target := t.TempDir()

	oldOpenMounts := openMounts
	openMounts = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("/dev/sda1 " + target + " ext4 rw 0 0\n")), nil
	}
	t.Cleanup(func() { openMounts = oldOpenMounts })

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want silence when no NFS mount contains target", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

type closeErrorReader struct {
	io.Reader
	err error
}

func (r closeErrorReader) Close() error { return r.err }

func TestMountCloseFailureUsesClosePrefix(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeSiblingTuning(t, executable, "version: 1\ntunings: []\n")

	oldOpenMounts := openMounts
	openMounts = func() (io.ReadCloser, error) {
		return closeErrorReader{
			Reader: strings.NewReader("192.0.2.1:/data " + target + " nfs4 rw 0 0\n"),
			err:    errors.New("close failed"),
		}, nil
	}
	t.Cleanup(func() { openMounts = oldOpenMounts })

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning: close /proc/mounts: close failed; using built-in defaults") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func TestTuningKeyResolutionFailureWarnsAndUsesBuiltIns(t *testing.T) {
	captured := captureRunConfig(t)
	executable := configureExecutablePath(t)
	writeSiblingTuning(t, executable, "version: 1\ntunings: []\n")

	oldHostname := hostname
	hostname = func() (string, error) { return "", errors.New("hostname unavailable") }
	t.Cleanup(func() { hostname = oldHostname })

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "WARNING: tuning: resolve client hostname: hostname unavailable; using built-in defaults") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func TestAbsentTuningFileIsSilent(t *testing.T) {
	captured := captureRunConfig(t)
	_, target := configureKernelTuningTest(t)

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want silence for an absent tuning file", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func TestPresentUnreadableTuningWarnsAndUsesBuiltIns(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	path := tuning.PathForExecutable(executable)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.HasPrefix(errOut.String(), "WARNING: tuning:") || !strings.Contains(errOut.String(), "; using built-in defaults") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	assertBuiltInParams(t, captured)
}

func TestMalformedTuningWarnsAndUsesBuiltIns(t *testing.T) {
	captured := captureRunConfig(t)
	executable, target := configureKernelTuningTest(t)
	writeSiblingTuning(t, executable, "version: [")

	var out, errOut strings.Builder
	code := runWithFlagSet([]string{"--spec", specFixture(t), target}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.HasPrefix(errOut.String(), "WARNING: tuning:") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "; using built-in defaults") {
		t.Fatalf("stderr = %q, want built-in fallback", errOut.String())
	}
	if captured.Connections != 16 || captured.Slots != 0 || captured.Workers != 0 || captured.BatchSize != 50 || captured.MaxOpsPerCompound != 0 {
		t.Fatalf("Run config = %+v, want command built-ins and the existing untyped-workers sentinel", *captured)
	}
}

func captureRunConfig(t *testing.T) *runpkg.Config {
	t.Helper()
	oldRun := runCommand
	captured := new(runpkg.Config)
	runCommand = func(_ context.Context, cfg runpkg.Config, _ io.Writer) (runpkg.Result, error) {
		*captured = cfg
		return runpkg.Result{}, nil
	}
	t.Cleanup(func() { runCommand = oldRun })
	return captured
}

func configureExecutablePath(t *testing.T) string {
	t.Helper()
	executable := filepath.Join(t.TempDir(), "permissionreset")
	oldExecutablePath := executablePath
	executablePath = func() (string, error) { return executable, nil }
	t.Cleanup(func() { executablePath = oldExecutablePath })
	return executable
}

func configureKernelTuningTest(t *testing.T) (executable, target string) {
	t.Helper()
	executable = configureExecutablePath(t)
	var err error
	target, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldOpenMounts := openMounts
	openMounts = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("192.0.2.1:/data " + target + " nfs4 rw 0 0\n")), nil
	}
	t.Cleanup(func() { openMounts = oldOpenMounts })
	return executable, target
}

func hostName(t *testing.T) string {
	t.Helper()
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func assertBuiltInParams(t *testing.T, captured *runpkg.Config) {
	t.Helper()
	if captured.Connections != 16 || captured.Slots != 0 || captured.Workers != 0 || captured.BatchSize != 50 || captured.MaxOpsPerCompound != 0 {
		t.Fatalf("Run config = %+v, want command built-ins and the existing untyped-workers sentinel", *captured)
	}
}

func writeMatchingTuning(t *testing.T, executable, server, export, transport string, params tuning.Params) {
	t.Helper()
	writeTuningEntries(t, executable, tuning.Entry{
		Clients:   []string{hostName(t)},
		Server:    server,
		Export:    export,
		Transport: transport,
		Params:    params,
		// A real sweep always records a confidence, and the announcement has to
		// carry it: a tuning measured on a drifting array is worth acting on
		// differently from one measured on a quiet one.
		Measured: tuning.Measured{Confidence: "low"},
	})
}

func writeTuningEntries(t *testing.T, executable string, entries ...tuning.Entry) {
	t.Helper()
	file := tuning.File{Version: tuning.Version, Tunings: entries}
	if err := tuning.Save(tuning.PathForExecutable(executable), file); err != nil {
		t.Fatal(err)
	}
}

func writeSiblingTuning(t *testing.T, executable, contents string) {
	t.Helper()
	if err := os.WriteFile(tuning.PathForExecutable(executable), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSecondSignalEscalates(t *testing.T) {
	sigCh := make(chan os.Signal, 2)
	runDone := make(chan struct{})
	escalated := make(chan os.Signal, 1)
	watchDone := make(chan struct{})
	var errOut strings.Builder
	go func() {
		signals.Watch(sigCh, runDone, &errOut, func(sig os.Signal) {
			escalated <- sig
		})
		close(watchDone)
	}()

	sigCh <- syscall.SIGINT
	sigCh <- syscall.SIGINT

	select {
	case got := <-escalated:
		if got != syscall.SIGINT {
			t.Fatalf("escalated signal = %v, want SIGINT", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second signal did not escalate")
	}
	<-watchDone
	if want := "interrupt received — finishing in-flight work..."; !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr = %q, want %q", errOut.String(), want)
	}
}

func TestExplicitZeroWorkersIsRejected(t *testing.T) {
	requireKernelTransport(t)
	root := t.TempDir()
	res := runBinary(t, root,
		"--spec", specFixture(t),
		"--workers", "0",
		root)
	if res.code == 0 {
		t.Fatalf("typed --workers 0 must be rejected; stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if want := "ERROR: --workers must be >= 1 (got 0)"; !strings.Contains(res.stderr, want) {
		t.Fatalf("stderr = %q, want %q", res.stderr, want)
	}
	if strings.Contains(res.stdout, "Workers:") {
		t.Fatalf("typed --workers 0 reached run defaulting; stdout=%q", res.stdout)
	}
}

// TestExitCodeForDistinguishesAnUnflushedCheckpoint holds the one thing that
// makes the sentinel worth exporting: automation deciding whether to retry with
// --resume must be able to tell "the repair failed, the checkpoint is fine" from
// "the repair succeeded, the checkpoint is not". Collapse 3 into 1 and a retry
// resumes from a file that does not describe the previous run.
func TestExitCodeForDistinguishesAnUnflushedCheckpoint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"repair failed", errors.New("permission repair run failed"), 1},
		{"interrupted", fmt.Errorf("run interrupted: %w", context.Canceled), 1},
		{"transport refusal", nfs41.ErrNotPureServer, 1},
		{"unflushed checkpoint", runpkg.ErrCheckpointUnflushed, 3},
		{"unflushed checkpoint, wrapped", fmt.Errorf("%w: fsync: no space left on device",
			runpkg.ErrCheckpointUnflushed), 3},
		// A pre-flight refusal is an ordinary failure. It happens before anything
		// is modified, so there is no checkpoint to distrust and nothing for
		// automation to resume -- collapsing it into 3 would tell a retry loop the
		// repair had succeeded.
		{"traverse not preserved", runpkg.ErrTraverseNotPreserved, 1},
		{"traverse not preserved, wrapped", fmt.Errorf("%w: default: directory mode 0644 removes all execute bits",
			runpkg.ErrTraverseNotPreserved), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeFor(tc.err); got != tc.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestUnflushedCheckpointAdviceReachesTheOperator covers both halves of the
// guidance line, and the second half is not a formality. Printing "your
// checkpoint is untrustworthy" after an ordinary failed repair would send an
// operator to re-repair a large tree from scratch when --resume was the correct
// move, so the line must be exactly as silent as it is loud.
func TestUnflushedCheckpointAdviceReachesTheOperator(t *testing.T) {
	const ckpt = "/var/tmp/run.ckpt"

	t.Run("present on the sentinel path", func(t *testing.T) {
		var errOut strings.Builder
		reportCheckpointUnflushed(&errOut,
			fmt.Errorf("%w: fsync: no space left on device", runpkg.ErrCheckpointUnflushed), ckpt)
		got := errOut.String()
		if !strings.Contains(got, ckpt) {
			t.Errorf("stderr = %q, want the checkpoint path named", got)
		}
		if !strings.Contains(got, "--resume") {
			t.Errorf("stderr = %q, want the advice to name --resume, the action to avoid", got)
		}
		if !strings.Contains(got, "the repair itself succeeded") {
			t.Errorf("stderr = %q, want it to say the repair succeeded, or the operator re-repairs for nothing", got)
		}
	})

	t.Run("names the checkpoint generically when no path is in scope", func(t *testing.T) {
		var errOut strings.Builder
		reportCheckpointUnflushed(&errOut, runpkg.ErrCheckpointUnflushed, "")
		if got := errOut.String(); !strings.Contains(got, "--resume") {
			t.Errorf("stderr = %q, want the advice even without a path to name", got)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ordinary repair failure", errors.New("permission repair run failed")},
		{"interrupted run", fmt.Errorf("run interrupted: %w", context.Canceled)},
		{"transport refusal", nfs41.ErrNotPureServer},
	} {
		t.Run("absent after "+tc.name, func(t *testing.T) {
			var errOut strings.Builder
			reportCheckpointUnflushed(&errOut, tc.err, ckpt)
			if got := errOut.String(); got != "" {
				t.Errorf("stderr = %q, want nothing: a failed repair leaves a usable checkpoint, and this advice would send the operator to re-repair from scratch", got)
			}
		})
	}
}

// TestTraverseAdviceReachesTheOperator pins the guidance text that survived the
// move of the traverse pre-flight into internal/run. The library reports which
// rule is at fault; only these two lines say what to change, and an operator who
// sees the diagnosis alone has no reason to suspect an execute bit on a directory
// rule rather than the target tree or the invoking account.
func TestTraverseAdviceReachesTheOperator(t *testing.T) {
	t.Run("present on the sentinel path", func(t *testing.T) {
		var errOut strings.Builder
		reportTraverseNotPreserved(&errOut, fmt.Errorf("%w: default: directory mode 0644 removes all execute bits",
			runpkg.ErrTraverseNotPreserved))
		got := errOut.String()
		if !strings.Contains(got, "The spec's directory permissions would lock the walk out of child directories.") {
			t.Errorf("stderr = %q, want the lockout explanation verbatim", got)
		}
		if !strings.Contains(got, "Add execute/traverse permission for the running identity to directory rules.") {
			t.Errorf("stderr = %q, want the remedy verbatim", got)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ordinary repair failure", errors.New("permission repair run failed")},
		{"unflushed checkpoint", runpkg.ErrCheckpointUnflushed},
		{"transport refusal", nfs41.ErrNotPureServer},
	} {
		t.Run("absent after "+tc.name, func(t *testing.T) {
			var errOut strings.Builder
			reportTraverseNotPreserved(&errOut, tc.err)
			if got := errOut.String(); got != "" {
				t.Errorf("stderr = %q, want nothing: the spec was not what went wrong", got)
			}
		})
	}
}

// TestExitCodeThreeIsNotAlreadyTaken guards the numbering. 0, 1 and 2 have
// meanings this command and the flag package already committed to; 3 was free,
// and renumbering any of the others would break existing automation.
func TestExitCodeThreeIsNotAlreadyTaken(t *testing.T) {
	if exitCodeFor(nil) == 3 {
		t.Error("success must not be 3")
	}
	if exitCodeFor(errors.New("anything else")) == 3 {
		t.Error("a generic failure must stay 1; 3 means only an unflushed checkpoint")
	}
}

// ---------------------------------------------------------------------------
// --json-summary
// ---------------------------------------------------------------------------

// A dry run over a local tree is the cheapest way to exercise the whole
// summary path: the flag, the digest of the spec actually loaded, the atomic
// write, and the enriched stdout block, all as an operator would see them.
func TestJSONSummaryIsWrittenAndMatchesStdout(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a", filepath.Join("sub", "b")} {
		if err := os.WriteFile(filepath.Join(tree, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(tmp, "run.json")
	specPath := specFixture(t)
	res := runBinary(t, tmp,
		"--spec", specPath,
		"--skip-identity-check",
		"--quiet",
		"--json-summary", out,
		tree)
	if res.code != 0 {
		t.Fatalf("want exit 0; got %d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("summary was not written: %v", err)
	}
	var got summary.RunSummary
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("summary is not valid JSON: %v\n%s", err, b)
	}

	if got.SchemaVersion != summary.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, summary.SchemaVersion)
	}
	if got.Transport.Name != "kernel" {
		t.Errorf("transport = %q, want kernel", got.Transport.Name)
	}
	if got.Transport.Server != "" || got.Transport.Export != "" {
		t.Errorf("kernel transport must report no server/export, got %q %q", got.Transport.Server, got.Transport.Export)
	}
	if got.Transport.FilesystemID == 0 || got.Transport.FilesystemIDSource != "st_dev" {
		t.Errorf("kernel transport should report st_dev, got id=%d source=%q",
			got.Transport.FilesystemID, got.Transport.FilesystemIDSource)
	}
	// The canonical path, not the path as typed.
	wantTarget, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != wantTarget {
		t.Errorf("target = %q, want the canonical %q", got.Target, wantTarget)
	}
	if got.Spec.Path != specPath {
		t.Errorf("spec.path = %q, want %q", got.Spec.Path, specPath)
	}
	wantDigest, err := summary.FileDigest(specPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.SHA256 != wantDigest {
		t.Errorf("spec.sha256 = %q, want %q", got.Spec.SHA256, wantDigest)
	}
	if !got.Options.DryRun {
		t.Error("a run without --apply must record dry_run true")
	}
	if !got.Options.WorkersDefault || got.Options.Workers != defaultWorkersFallback {
		t.Errorf("workers = %d defaulted=%t, want %d defaulted",
			got.Options.Workers, got.Options.WorkersDefault, defaultWorkersFallback)
	}
	if got.Objects.Enumerated < 3 {
		t.Errorf("enumerated = %d, want at least the three objects created", got.Objects.Enumerated)
	}
	if got.Objects.Applied != got.Objects.Enumerated || got.Errors.Total != 0 {
		t.Errorf("clean dry run should apply everything with no errors: %+v %+v", got.Objects, got.Errors)
	}
	if got.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", got.ExitCode)
	}
	// A dry run writes nothing and checks nothing: it must not read as verified.
	if got.Verification.Verdict != summary.VerdictNotRequested || got.Accounting.Attempted != 0 ||
		got.Accounting.Unverified != got.Objects.Enumerated || len(got.RunID) != 32 {
		t.Errorf("dry run verification = %q, accounting %+v, run_id %q", got.Verification.Verdict, got.Accounting, got.RunID)
	}
	if _, err := summary.Decode(b); err != nil {
		t.Errorf("written summary does not decode: %v", err)
	}
	if got.StartedAt == "" || got.FinishedAt == "" {
		t.Errorf("timestamps missing: %q %q", got.StartedAt, got.FinishedAt)
	}

	// The counts block predates this feature and scripts read it; it must still
	// be there, and the enriched block must be additive.
	for _, line := range []string{"\nComplete:\n", "  Enumerated: ", "  Applied:    ", "\nRun detail:\n", "  Spec sha256: " + wantDigest, "  Exit code:  0"} {
		if !strings.Contains(res.stdout, line) {
			t.Errorf("stdout missing %q\nstdout: %s", line, res.stdout)
		}
	}

	// Nothing but the summary may be left in the output directory: the write is
	// a temp file plus a rename, and the temp file must not survive.
	ents, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != "tree" && e.Name() != "run.json" {
			t.Errorf("unexpected leftover %q in the output directory", e.Name())
		}
	}
}

// Without the flag, no file appears and the run is otherwise unchanged.
func TestNoJSONSummaryWithoutTheFlag(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runBinary(t, tmp, "--spec", specFixture(t), "--skip-identity-check", "--quiet", tree)
	if res.code != 0 {
		t.Fatalf("want exit 0; got %d stderr=%s", res.code, res.stderr)
	}
	ents, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("a run without --json-summary wrote something: %d entries", len(ents))
	}
	if strings.Contains(res.stdout, "Summary:") {
		t.Errorf("stdout claims a summary was written:\n%s", res.stdout)
	}
}

// An unwritable summary path is reported and raises the exit code: a harness
// that asked for the file and did not get it must not see success.
func TestUnwritableJSONSummaryFailsTheRun(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runBinary(t, tmp, "--spec", specFixture(t), "--skip-identity-check", "--quiet",
		"--json-summary", filepath.Join(tmp, "no-such-dir", "run.json"), tree)
	if res.code == 0 {
		t.Errorf("want a nonzero exit when the summary cannot be written\nstdout=%s\nstderr=%s", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "write JSON summary") {
		t.Errorf("stderr should explain the summary failure: %s", res.stderr)
	}
}

// --evidence-dir end to end: the summary's records and evidence block come
// from the manifest the run wrote, and they agree with the shards on disk.
func TestEvidenceDirReachesSummary(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"a", filepath.Join("sub", "b")} {
		if err := os.WriteFile(filepath.Join(tree, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	evDir := filepath.Join(tmp, "evidence")
	out := filepath.Join(tmp, "run.json")
	res := runBinary(t, tmp, "--spec", specFixture(t), "--skip-identity-check", "--quiet",
		"--evidence-dir", evDir, "--json-summary", out, tree)
	if res.code != 0 {
		t.Fatalf("exit %d\nstdout=%s\nstderr=%s", res.code, res.stdout, res.stderr)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got summary.RunSummary
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Evidence == nil || got.Evidence.Status != evidence.StatusComplete || got.Options.EvidenceDir != evDir {
		t.Fatalf("summary evidence = %+v, options.evidence_dir = %q", got.Evidence, got.Options.EvidenceDir)
	}
	mb, err := os.ReadFile(filepath.Join(evDir, evidence.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m evidence.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	if m.RunID == "" || m.RunID != got.RunID {
		t.Errorf("manifest run_id %q != summary run_id %q", m.RunID, got.RunID)
	}
	if len(got.Records) != len(m.Shards) || len(m.Shards) == 0 {
		t.Fatalf("summary has %d shard refs, manifest %d", len(got.Records), len(m.Shards))
	}
	for i, ref := range got.Records {
		digest, err := summary.FileDigest(ref.Path)
		if err != nil || digest != ref.SHA256 || ref.Records != m.Shards[i].Records {
			t.Errorf("shard ref %+v does not match the file (digest %s, err %v)", ref, digest, err)
		}
	}
	if !strings.HasSuffix(m.Shards[0].Path, ".gz") {
		t.Errorf("shards are gzipped by default; got %s", m.Shards[0].Path)
	}
}

// --audit-log still works, with a deprecation warning: it names the evidence
// directory and keeps its old shape, one uncompressed file of records.
func TestAuditLogIsDeprecatedEvidence(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(tree, "a"), nil, 0o644)
	dir := filepath.Join(tmp, "audit")
	res := runBinary(t, tmp, "--spec", specFixture(t), "--skip-identity-check", "--quiet", "--audit-log", dir, tree)
	if res.code != 0 {
		t.Fatalf("exit %d\nstderr=%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "--audit-log is deprecated") {
		t.Errorf("no deprecation warning: %s", res.stderr)
	}
	b, err := os.ReadFile(filepath.Join(dir, "shard-000001.log"))
	if err != nil {
		t.Fatalf("the single uncompressed shard is missing: %v", err)
	}
	if !strings.Contains(string(b), filepath.Join(tree, "a")) {
		t.Errorf("records = %q", b)
	}
}

func TestEvidenceFlagRefusals(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "old-audit.log")
	os.WriteFile(file, nil, 0o644)
	used := filepath.Join(tmp, "used")
	os.MkdirAll(used, 0o755)
	os.WriteFile(filepath.Join(used, "x"), nil, 0o644)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"both spellings", []string{"--audit-log", filepath.Join(tmp, "a"), "--evidence-dir", filepath.Join(tmp, "b")}, "both name evidence"},
		{"audit-log is a file", []string{"--audit-log", file}, "is a file"},
		{"unknown profile", []string{"--evidence-dir", filepath.Join(tmp, "c"), "--evidence-profile", "verbose"}, "unknown evidence profile"},
		{"zero shard size", []string{"--evidence-dir", filepath.Join(tmp, "d"), "--evidence-shard-mb", "0"}, "--evidence-shard-mb"},
		{"used directory", []string{"--evidence-dir", used}, "not empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut strings.Builder
			args := append([]string{"--spec", specFixture(t), "--skip-identity-check"}, tc.args...)
			args = append(args, tmp)
			if code := runWithFlagSet(args, &out, &errOut); code != 1 {
				t.Fatalf("exit %d, want 1; stderr=%s", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("stderr = %q, want %q", errOut.String(), tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// --checkpoint + --dry-run / --validate rejection
// ---------------------------------------------------------------------------

func TestCheckpointWithExplicitDryRunIsRefused(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runBinary(t, tmp,
		"--spec", specFixture(t),
		"--skip-identity-check",
		"--dry-run",
		"--checkpoint", filepath.Join(tmp, "cp"),
		tree)
	if res.code == 0 {
		t.Fatal("want nonzero exit when --checkpoint is used with --dry-run")
	}
	if !strings.Contains(res.stderr, "checkpoint") {
		t.Errorf("stderr = %q, want it to mention checkpoint", res.stderr)
	}
}

func TestCheckpointWithValidateIsRefused(t *testing.T) {
	requireKernelTransport(t)
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	res := runBinary(t, tmp,
		"--spec", specFixture(t),
		"--skip-identity-check",
		"--validate",
		"--checkpoint", filepath.Join(tmp, "cp"),
		tree)
	if res.code == 0 {
		t.Fatal("want nonzero exit when --checkpoint is used with --validate")
	}
	if !strings.Contains(res.stderr, "checkpoint") {
		t.Errorf("stderr = %q, want it to mention checkpoint", res.stderr)
	}
}

// ---------------------------------------------------------------------------
// Platform gating
// ---------------------------------------------------------------------------

// helpFlagNames returns the flag names --help actually lists, by parsing the
// "  -name" lines the custom fs.Usage emits. Substring matching against the
// whole help text is not good enough: "-no-pfind" contains "-pfind", and any
// usage string mentioning "--transport=userspace" contains "-transport".
func helpFlagNames(t *testing.T, help string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		if !strings.HasPrefix(line, "  -") {
			continue
		}
		names[strings.TrimSpace(strings.TrimPrefix(line, "  -"))] = true
	}
	if len(names) == 0 {
		t.Fatalf("parsed no flag names out of --help; the output format changed:\n%s", help)
	}
	return names
}

func helpOutput(t *testing.T) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := runWithFlagSet([]string{"-help"}, &out, &errOut); code != 0 {
		t.Fatalf("-help exit code = %d, want 0", code)
	}
	return out.String() + errOut.String()
}

// writeTempSpec writes a spec file into a per-test tmpdir and returns its path.
// Offline by construction: nothing here touches a mount.
func writeTempSpec(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	return path
}

func TestDarwinHidesUnavailableFlagsFromHelp(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())
	names := helpFlagNames(t, helpOutput(t))

	for _, hidden := range []string{"pfind", "no-pfind"} {
		if names[hidden] {
			t.Errorf("-%s appears in --help on darwin; RapidFile does not exist there", hidden)
		}
	}
	// --transport is NOT hidden. userspace is the value that works here and the
	// value the docs teach; hiding the flag would make the shipped docs
	// contradict the binary. Only the value "kernel" is refused.
	if !names["transport"] {
		t.Error("-transport is missing from --help on darwin; --transport=userspace is valid there")
	}
	for _, shown := range []string{"server", "export", "connections"} {
		if !names[shown] {
			t.Errorf("-%s missing from --help on darwin; it is mandatory there", shown)
		}
	}
	// No usage string may qualify anything with a transport choice that does not
	// exist on this build -- including -workers, whose text is hardcoded today.
	if strings.Contains(helpOutput(t), "--transport=userspace") {
		t.Error("--help on darwin still names a transport choice the operator does not have")
	}
}

func TestLinuxKeepsEveryFlagInHelp(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Linux())
	names := helpFlagNames(t, helpOutput(t))

	for _, shown := range []string{"transport", "pfind", "no-pfind"} {
		if !names[shown] {
			t.Errorf("-%s missing from --help on linux", shown)
		}
	}
	if !strings.Contains(helpOutput(t), "--transport=userspace only") {
		t.Error("linux --help lost the userspace-only qualifier")
	}
}

// The completeness test: every flag this command registers is classified, so a
// future mount-dependent flag added with a plain fs.Bool cannot ship visible on
// macOS. On macOS the compiler will not catch it and the first Mac operator to
// use it gets an ENOTSUP per object hours into a run -- exactly what gating
// exists to prevent.
//
// Adding a flag means adding its name to one of these two sets. That is the
// point: the choice is forced at the moment the flag is written, by a test that
// names the decision, rather than deferred to whoever debugs the field report.
func TestEveryFlagIsClassified(t *testing.T) {
	// portable: works identically on every platform this version ships.
	portable := map[string]bool{
		"spec": true, "workers": true, "dry-run": true, "validate": true, "log": true,
		"audit-log": true, "evidence-dir": true, "evidence-profile": true,
		"evidence-shard-mb": true, "evidence-gzip": true, "compare": true, "checkpoint": true, "resume": true,
		"quiet": true, "json-summary": true, "set-owner": true, "batch-size": true,
		"apply": true, "skip-identity-check": true, "exclude": true,
		"one-filesystem": true, "version": true, "server": true, "export": true,
		"connections": true, "slots": true, "max-ops-per-compound": true,
		"rpc-timeout": true, "retry-budget": true, "retry-base-delay": true,
		"unsafe-allow-non-pure-server": true, "support-bundle": true, "no-redact": true,
		"cpuprofile": true, "memprofile": true, "memprofile-interval": true,
		"rpc-stats": true,
		"auth-uid":  true, "auth-gid": true, "auth-gids": true, "auth-hostname": true,
		"sacl":                     true,
		"accept-dacl-flattening":   true,
		"allow-high-ids":           true,
		"allow-audited-dacl-reset": true,
		"partitions":               true,
		"partition":                true,
		// transport is value-gated, not presence-gated: the flag is portable,
		// one of its values is not. TestDarwinRefusesTheKernelTransport covers it.
		"transport": true,
	}
	// gated: refused outright where the capability is absent.
	gated := map[string]bool{"pfind": true, "no-pfind": true}

	fs, _ := registerFlags(flag.NewFlagSet("classify", flag.ContinueOnError), io.Discard)
	fs.VisitAll(func(f *flag.Flag) {
		if portable[f.Name] == gated[f.Name] { // in neither, or in both
			t.Errorf("flag -%s is unclassified: add it to `portable` if it works on every "+
				"platform, or gate it and add it to `gated`. On macOS the compiler will not "+
				"catch a mount-dependent flag; this test is what does.", f.Name)
		}
	})

	// VisitAll above catches an UNCLASSIFIED flag. It cannot catch a MISCLASSIFIED
	// one: a flag registered through the gate but listed in `portable` satisfies
	// the check and still refuses on macOS. Ask the gate itself what it refuses.
	// Registration must run under absent capabilities, because Gate only records
	// a flag when the capability it needs is missing.
	assertGatedSetMatches(t, gated)
}

// assertGatedSetMatches compares a command's hand-written `gated` set against
// what its Gate actually refuses, in both directions.
func assertGatedSetMatches(t *testing.T, gated map[string]bool) {
	t.Helper()
	cmdflagstest.With(t, &caps, platform.Darwin())

	_, f := registerFlags(flag.NewFlagSet("gatecheck", flag.ContinueOnError), io.Discard)
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

func TestDarwinRefusesTheKernelTransport(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := runWithFlagSet([]string{"-transport", "kernel", "-spec", "x.yaml", "/tmp"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	got := errOut.String()
	for _, want := range []string{"--transport=kernel", "system.nfs4_acl", "--transport=userspace"} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
	if strings.Contains(got, "requires Linux") {
		t.Errorf("error = %q, blames an operating system rather than naming the capability", got)
	}
}

// The value gate must not fire on the value that works. This is the exact
// command line INSTALL.md and docs/transports.md teach a Mac operator, so a
// refusal here ships docs that contradict the binary.
func TestDarwinAcceptsTheUserspaceTransport(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	specPath := writeTempSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\n")
	var out, errOut bytes.Buffer
	code := runWithFlagSet([]string{"-transport", "userspace", "-spec", specPath, "/tmp/whatever"},
		&out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	// The only complaint may be the mandatory-argument one, which is correct:
	// there is no mounted path to infer --server and --export from.
	got := errOut.String()
	if !strings.Contains(got, "requires --server and --export") {
		t.Fatalf("error = %q, want only the userspace mandatory-argument error", got)
	}
	if strings.Contains(got, "unavailable on this build") {
		t.Fatalf("error = %q, refused the transport that works here", got)
	}
}

func TestDarwinRefusesExplicitPfind(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := runWithFlagSet([]string{"-pfind", "-spec", "x.yaml", "/tmp"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if got := errOut.String(); !strings.Contains(got, "--pfind is unavailable") {
		t.Fatalf("error = %q, want the capability refusal", got)
	}
}

// --no-pfind is a deprecated alias for a Linux-only feature. It was accepted
// silently on macOS before this task.
func TestDarwinRefusesExplicitNoPfind(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := runWithFlagSet([]string{"-no-pfind", "-spec", "x.yaml", "/tmp"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if got := errOut.String(); !strings.Contains(got, "--no-pfind is unavailable") {
		t.Fatalf("error = %q, want the capability refusal", got)
	}
}

// The whole point of moving the default: a Mac command line that names no
// transport must not land on the kernel backend, which would compile, run a
// real setxattr, and fail ENOTSUP per object.
func TestDarwinDefaultsToUserspace(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())
	if got := defaultTransport(); got != "userspace" {
		t.Fatalf("defaultTransport() = %q on darwin, want userspace", got)
	}

	specPath := writeTempSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\n")
	var out, errOut bytes.Buffer
	code := runWithFlagSet([]string{"-spec", specPath, "/tmp/whatever"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if got := errOut.String(); !strings.Contains(got, "requires --server and --export") {
		t.Fatalf("error = %q, want the userspace mandatory-argument error", got)
	}
}

func TestLinuxDefaultsToKernel(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Linux())
	if got := defaultTransport(); got != "kernel" {
		t.Fatalf("defaultTransport() = %q on linux, want kernel", got)
	}
}

// withoutCredentialNote strips the userspace credential diagnostics -- the
// dry-run note and the uid warnings -- which are unconditional on that path and
// are not what any tuning-announcement test is asserting about.
func withoutCredentialNote(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		// The uid warnings are credential diagnostics, not tuning announcements,
		// and one of them fires whenever the suite runs as root -- which is how
		// a rootful CI container runs it.
		if line == "" ||
			strings.HasPrefix(line, "note: the AUTH_SYS credential has not been exercised") ||
			strings.HasPrefix(line, "WARNING: the AUTH_SYS uid is") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// The four AUTH_SYS flags are discoverable. They are the only way to present an
// identity the array's directory knows from a host whose local uids mean
// nothing to it, so a flag that exists but is undocumented is not a fix.
func TestPermissionResetAcceptsTheAuthFlags(t *testing.T) {
	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"-help"}, &out, &errOut); code != 0 {
		t.Fatalf("-help exit code = %d, want 0", code)
	}
	help := out.String() + errOut.String()
	for _, want := range []string{"-auth-uid", "-auth-gid", "-auth-gids", "-auth-hostname"} {
		if !strings.Contains(help, want) {
			t.Errorf("%s missing from permissionreset --help", want)
		}
	}
}

// The credential reaches the run config, not just the flag set.
func TestPermissionResetPassesTheCredentialIntoTheRunConfig(t *testing.T) {
	captured := captureRunConfig(t)
	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"--auth-uid", "10010",
		"--auth-gid", "10000",
		"--auth-gids", "10020,10021",
		"--auth-hostname", "lab-client",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d stderr = %s", code, errOut.String())
	}
	if captured.Auth == nil {
		t.Fatal("run config Auth = nil, want the credential from the flags")
	}
	if captured.Auth.UID != 10010 || captured.Auth.GID != 10000 || captured.Auth.Machine != "lab-client" {
		t.Fatalf("run config Auth = %+v, want uid 10010 gid 10000 machine lab-client", captured.Auth)
	}
	if len(captured.Auth.AuxGIDs) != 2 {
		t.Fatalf("aux gids = %v, want two", captured.Auth.AuxGIDs)
	}
}

// Naming no flag leaves the credential nil, so nfs41 builds it from the process
// exactly as it did before this flag surface existed.
func TestPermissionResetLeavesTheCredentialNilWhenNothingIsTyped(t *testing.T) {
	captured := captureRunConfig(t)
	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d stderr = %s", code, errOut.String())
	}
	if captured.Auth != nil {
		t.Fatalf("run config Auth = %+v, want nil so nfs41 builds the process credential", captured.Auth)
	}
}

// A userspace dry run says the credential has not been exercised: preflight's
// real ACL write happens only under --apply, so a clean-looking plan proves
// nothing about who the array thinks you are.
func TestUserspaceDryRunSaysTheCredentialIsUnexercised(t *testing.T) {
	captureRunConfig(t)
	var out, errOut strings.Builder
	code := runWithFlagSet([]string{
		"--spec", specFixture(t),
		"--transport=userspace",
		"--server=192.0.2.1",
		"--export=/data",
		"/data",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code = %d stderr = %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "AUTH_SYS credential has not been") {
		t.Fatalf("stderr = %q, want the credential note", errOut.String())
	}
}

// --validate returns from run.Run at the cfg.Validate branch, before
// ProbePreflight, so it never exercises the credential -- and it does that even
// under --apply, which is the combination the note used to miss entirely. A
// clean validate report over a squashed credential is the exact false negative
// the note exists to prevent, so it must print on every --validate run.
func TestUserspaceValidateSaysTheCredentialIsUnexercised(t *testing.T) {
	for _, args := range [][]string{
		{"--validate"},
		{"--validate", "--apply"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			captureRunConfig(t)
			var out, errOut strings.Builder
			code := runWithFlagSet(append([]string{
				"--spec", specFixture(t),
				"--transport=userspace",
				"--server=192.0.2.1",
				"--export=/data",
			}, append(args, "/data")...), &out, &errOut)
			if code != 0 {
				t.Fatalf("code = %d stderr = %s", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), "AUTH_SYS credential has not been") {
				t.Fatalf("stderr = %q, want the credential note", errOut.String())
			}
		})
	}
}

// The value must follow --transport, not the build platform: a Linux
// --transport=userspace run talks to the same array a Mac does, and the array
// is the authority for both.
func TestLocalIdentityAuthoritativeFollowsTheSelectedTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		args      func(t *testing.T) []string
		want      bool
	}{
		{"kernel", func(t *testing.T) []string {
			return []string{"--spec", specFixture(t), "--transport=kernel", t.TempDir()}
		}, true},
		{"userspace", func(t *testing.T) []string {
			return []string{"--spec", specFixture(t), "--transport=userspace",
				"--server=192.0.2.1", "--export=/data", "/data/subdir"}
		}, false},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			// Linux capabilities: KernelTransport is true for BOTH subtests,
			// so a wiring that reads caps instead of the flag fails the
			// userspace case here.
			cmdflagstest.With(t, &caps, platform.Linux())

			captured := captureRunConfig(t)
			var out, errOut strings.Builder
			if code := runWithFlagSet(tc.args(t), &out, &errOut); code != 0 {
				t.Fatalf("code = %d stderr = %s", code, errOut.String())
			}
			if captured.LocalIdentityAuthoritative != tc.want {
				t.Fatalf("LocalIdentityAuthoritative = %v with --transport=%s, want %v",
					captured.LocalIdentityAuthoritative, tc.transport, tc.want)
			}
		})
	}
}
