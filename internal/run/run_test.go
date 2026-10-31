package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestApplyCallSitesCarryTheFilehandle guards the one line this whole task is
// about. internal/nfs41's TestWalkThenApplyIssuesNoLookups measures the round
// trips and dies if walk.Entry.Ref drops the filehandle, but it cannot see this
// package: Run is driven here against a real filesystem, and there is no fake
// NFS server on this side to count LOOKUPs against. Inlining
// transport.Ref{Path: e.Path} back into the entry loops would therefore restore
// a LOOKUP per object with every test still green — the run would be correct,
// just slower, which is exactly how the defect survived the first time.
//
// Reading our own source is a blunt instrument and will need updating if the
// entry loops are restructured. It is deliberate: a false failure here costs one
// edit, and the alternative is no coverage at all. It moved with the call sites
// during the "Put permission repair behind one reusable run boundary" commit.
//
// Reviewed and kept at Task 12b review, with the patterns widened. The literal
// substring form failed for reasons that were not the defect -- renaming the loop
// variable, or writing transport.Ref{Path: e.Path, FH: nil}, moved the text
// without changing the behaviour in either direction. The forms below assert the
// shape instead: the second argument of each call must be some variable's Ref(),
// and no transport.Ref literal may be built out of an entry's Path.
//
// Only the ProcessPath site can carry a filehandle today. --validate is refused
// under --transport=userspace (see the transport gate in the command), so
// runValidate always sees Entry.FH nil; that half of this test is a forward guard
// for whenever --validate does reach the userspace transport, not current coverage.
func TestApplyCallSitesCarryTheFilehandle(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate run_test.go")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "run.go"))
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	text := string(src)

	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`apply\.ProcessPath\(\s*\w+,\s*\w+\.Ref\(\)\s*,`),
		regexp.MustCompile(`apply\.ValidatePath\(\s*\w+,\s*[\w.]+\.Ref\(\)\s*,`),
	} {
		if !want.MatchString(text) {
			t.Errorf("run.go has no call matching %v; the apply call sites must pass walk.Entry.Ref() so the filehandle READDIR returned reaches the transport", want)
		}
	}
	if m := regexp.MustCompile(`transport\.Ref\{[^}]*\b(?:e|ent|entry)\.Path\b`).FindString(text); m != "" {
		t.Errorf("run.go builds a transport.Ref from an entry path alone (%q), discarding the filehandle READDIR already returned; pass e.Ref() instead", m)
	}
}

func TestDefaultWorkersTable(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		platform  nfs41.Platform
		want      int
	}{
		{"userspace on FlashBlade", "userspace", nfs41.PlatformFlashBlade, 1024},
		{"kernel", "kernel", nfs41.PlatformUnknown, 128},
		{"kernel never inherits the userspace tuning", "kernel", nfs41.PlatformFlashBlade, 128},
		{"userspace on an unidentified server", "userspace", nfs41.PlatformUnknown, 128},
		{"unknown transport", "banana", nfs41.PlatformUnknown, 128},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultWorkers(tc.transport, tc.platform); got != tc.want {
				t.Errorf("defaultWorkers(%q, %q) = %d, want %d", tc.transport, tc.platform, got, tc.want)
			}
		})
	}
}

// writeSpec writes a spec file and loads it, which every close-path test below
// needs before it can call Run.
func writeSpec(t *testing.T, body string) (string, *spec.Spec) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := spec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, loaded
}

// posixSpec fixes directories to 0755 and files to 0644.
//
// The file mode is carried by an explicit file rule rather than by the default,
// and the default is itself traversable, because apply.CheckTraversePreserved
// inspects the default as if it were a directory mode. A default of 0644 with a
// directory rule overriding it describes the same repair -- a matching rule
// replaces the default entirely, so no directory ever reads the default -- but it
// is refused by the pre-flight check. Spelling both modes as rules keeps the
// fixture a spec the tool actually accepts.
const posixSpec = "protocol: posix\ndefault:\n  mode: \"0755\"\nrules:\n" +
	"  - match:\n      type: directory\n    mode: \"0755\"\n" +
	"  - match:\n      type: file\n    mode: \"0644\"\n"

// failClose replaces one of the close seams for the duration of a test.
func failCloseTransport(t *testing.T, err error) {
	t.Helper()
	prev := closeTransport
	closeTransport = func(transport.Transport) error { return err }
	t.Cleanup(func() { closeTransport = prev })
}

func failCloseCheckpoint(t *testing.T, err error) {
	t.Helper()
	prev := closeCheckpoint
	closeCheckpoint = func(*checkpoint.Checkpoint) error { return err }
	t.Cleanup(func() { closeCheckpoint = prev })
}

// TestTransportCloseFailureIsAWarningAndNotAFailure pins the non-fatal half of
// the split. A DESTROY_SESSION that never lands leaves a session the server
// expires by itself, so the run is still a success and must say so with a prefix
// that does not contradict its own exit status.
func TestTransportCloseFailureIsAWarningAndNotAFailure(t *testing.T) {
	failCloseTransport(t, errors.New("DESTROY_SESSION timed out"))
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil: a failed transport close must not fail the run", err)
	}
	stderr := errOut.String()
	if !strings.Contains(stderr, "WARNING: close transport: DESTROY_SESSION timed out") {
		t.Errorf("stderr = %q, want a WARNING naming the close failure", stderr)
	}
	if !strings.Contains(stderr, "expires server-side") {
		t.Errorf("stderr = %q, want the warning to say why the failure is harmless", stderr)
	}
	if strings.Contains(stderr, "ERROR: close transport") {
		t.Errorf("stderr = %q, want no ERROR prefix beside a successful run", stderr)
	}
}

// TestCheckpointCloseFailureReturnsTheSentinel pins the fatal half. The repair
// succeeded, so the failure is not "the repair failed" -- it is "the file a later
// --resume would read does not describe this run".
func TestCheckpointCloseFailureReturnsTheSentinel(t *testing.T) {
	failCloseCheckpoint(t, errors.New("fsync: no space left on device"))
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)

	var out, errOut strings.Builder
	got, err := Run(context.Background(), Config{
		Root:           root,
		SpecPath:       specPath,
		Spec:           loadedSpec,
		Transport:      "kernel",
		Workers:        1,
		BatchSize:      1,
		Apply:          true,
		Quiet:          true,
		CheckpointPath: filepath.Join(t.TempDir(), "ckpt"),
		ErrOut:         &errOut,
	}, &out)
	if !errors.Is(err, ErrCheckpointUnflushed) {
		t.Fatalf("Run() error = %v, want ErrCheckpointUnflushed", err)
	}
	if errors.Is(err, errRunFailed) {
		t.Errorf("Run() error = %v, must not claim the repair failed: it succeeded", err)
	}
	// The wrapping must keep the underlying cause matchable and readable.
	if !strings.Contains(err.Error(), "no space left on device") {
		t.Errorf("Run() error = %q, want the close error preserved in the message", err)
	}
	if got.Stats.Applied == 0 {
		t.Errorf("Run() result = %+v, want the repair itself to have applied work", got)
	}
	if !strings.Contains(errOut.String(), "ERROR: close checkpoint: fsync: no space left on device") {
		t.Errorf("stderr = %q, want the human-readable close error", errOut.String())
	}
}

// TestTraverseLockoutIsRefusedBeforeAnythingIsModified pins the pre-flight that
// moved here from the command when orchestration was extracted.
//
// A spec that strips execute from directories locks the walk out of the children
// of every directory it has already fixed, so the repair stops partway down and
// reports the part it managed to reach as the whole tree -- a silent incomplete
// repair, which is worse than a refusal because nothing signals it. The check has
// to run before the first modification for the refusal to be free of cost.
func TestTraverseLockoutIsRefusedBeforeAnythingIsModified(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// 0644 on directories: no execute for anyone.
	specPath, loadedSpec := writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0644\"\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if !errors.Is(err, ErrTraverseNotPreserved) {
		t.Fatalf("Run() error = %v, want ErrTraverseNotPreserved", err)
	}
	// The wrapping keeps the offending rule matchable, not just the category.
	if !strings.Contains(err.Error(), "execute") {
		t.Errorf("Run() error = %q, want the underlying cause preserved", err)
	}
	if !strings.Contains(errOut.String(), "ERROR:") {
		t.Errorf("stderr = %q, want the condition reported", errOut.String())
	}
	// Nothing may have been touched: the refusal is worthless if it lands after
	// the tree has already been half-rewritten.
	info, statErr := os.Stat(sub)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Errorf("sub mode = %04o, want 0755 unchanged: the run modified the tree before refusing", got)
	}
}

// TestTraverseCheckRunsBeforeIdentityPreResolve fixes the order of the two
// pre-flights. Both refuse the run, so either can mask the other, and the spec
// author needs the traverse verdict first: identity resolution depends on the
// host's idmap and can fail for reasons that have nothing to do with the spec,
// while a directory mode with no execute bit is wrong on its face.
func TestTraverseCheckRunsBeforeIdentityPreResolve(t *testing.T) {
	root := t.TempDir()
	// Both faults at once: no execute on directories, and an owner no host
	// resolves.
	specPath, loadedSpec := writeSpec(t,
		"protocol: posix\ndefault:\n  mode: \"0644\"\n  owner: no-such-user-9d3f1a\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if !errors.Is(err, ErrTraverseNotPreserved) {
		t.Fatalf("Run() error = %v, want the traverse verdict to win over identity pre-resolve", err)
	}
	if strings.Contains(errOut.String(), "identity pre-resolution failed") {
		t.Errorf("stderr = %q, want the run to stop at the traverse check", errOut.String())
	}
}

// TestFailedRepairOutranksAnUnflushedCheckpoint is the precedence case. The
// checkpoint close runs in a defer, after the verdict is known, and must not
// relabel a failed repair as a merely stale checkpoint -- the command maps the
// two to different exit codes, so relabelling would report a failed run as a
// successful one.
func TestFailedRepairOutranksAnUnflushedCheckpoint(t *testing.T) {
	failCloseCheckpoint(t, errors.New("fsync: no space left on device"))
	root := t.TempDir()
	// An owner that resolves to no account fails PreResolveIdentities, which runs
	// after the checkpoint is opened, so both failures are live at once. The
	// pre-resolution failure is only fatal where the local directory is the
	// authority, which is what the kernel transport a real command would pass
	// here means -- so say so explicitly.
	specPath, loadedSpec := writeSpec(t,
		"protocol: posix\ndefault:\n  mode: \"0755\"\n  owner: no-such-user-9d3f1a\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:                       root,
		SpecPath:                   specPath,
		Spec:                       loadedSpec,
		Transport:                  "kernel",
		LocalIdentityAuthoritative: true,
		Workers:                    1,
		BatchSize:                  1,
		Apply:                      true,
		Quiet:                      true,
		CheckpointPath:             filepath.Join(t.TempDir(), "ckpt"),
		ErrOut:                     &errOut,
	}, &out)
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want the repair failure to survive", err)
	}
	if errors.Is(err, ErrCheckpointUnflushed) {
		t.Fatalf("Run() error = %v: a deferred checkpoint close replaced the repair failure, which downgrades a failed run to a checkpoint warning", err)
	}
}

func TestRunRejectsNilSpec(t *testing.T) {
	got, err := Run(context.Background(), Config{}, nil)
	if err == nil || err.Error() != "nil permission spec" {
		t.Fatalf("Run() error = %v, want nil permission spec", err)
	}
	if !reflect.DeepEqual(got, Result{}) {
		t.Fatalf("Run() result = %+v, want zero result", got)
	}
}

// TestRunRefusesMissingSACLInSaclMode is the SACL guard itself: under --sacl
// (Config.Sacl), an NFSv4 spec that sets acl: with no sacl: key must be
// refused before the transport is even constructed -- on FlashArray that
// write would delete the object's existing audit ACEs, and the guard exists so
// that happens loudly at load time instead of silently at every matched object.
func TestRunRefusesMissingSACLInSaclMode(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t,
		"protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		Sacl:      true,
		ErrOut:    &errOut,
	}, &out)
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want errRunFailed", err)
	}
	if !strings.Contains(errOut.String(), "no sacl: key") {
		t.Errorf("stderr = %q, want it to name the missing sacl: key", errOut.String())
	}
	if !strings.Contains(errOut.String(), "default") {
		t.Errorf("stderr = %q, want it to name the offending rule (default)", errOut.String())
	}
}

// TestRunWithoutSaclModeAllowsACLOnly is the default: without --sacl the same
// spec runs, as every acl: spec did before SACL support existed.
func TestRunWithoutSaclModeAllowsACLOnly(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t,
		"protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if errors.Is(err, errRunFailed) && strings.Contains(errOut.String(), "sacl") {
		t.Fatalf("Run() refused an acl:-only spec without --sacl: err=%v stderr=%q", err, errOut.String())
	}
}

// TestRunRefusesSaclWithoutSaclMode: a spec that names sacl: -- even sacl: [],
// which deletes audit ACEs -- is refused unless --sacl is passed.
func TestRunRefusesSaclWithoutSaclMode(t *testing.T) {
	for name, body := range map[string]string{
		"keep-dacl": "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n",
		"empty":     "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n  sacl: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			specPath, loadedSpec := writeSpec(t, body)
			var out, errOut strings.Builder
			_, err := Run(context.Background(), Config{
				Root:      t.TempDir(),
				SpecPath:  specPath,
				Spec:      loadedSpec,
				Transport: "kernel",
				Workers:   1,
				BatchSize: 1,
				Apply:     true,
				Quiet:     true,
				ErrOut:    &errOut,
			}, &out)
			if !errors.Is(err, errRunFailed) || !strings.Contains(errOut.String(), "--sacl") {
				t.Fatalf("Run() err=%v stderr=%q, want a refusal naming --sacl", err, errOut.String())
			}
		})
	}
}

// TestRunDoesNotRefuseWhenSaclIsSet covers the way to satisfy the guard in
// SACL mode: the spec names sacl: (empty or not) on the rule that matters.
func TestRunDoesNotRefuseWhenSaclIsSet(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t,
		"protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n  sacl: []\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		Sacl:      true,
		ErrOut:    &errOut,
	}, &out)
	if errors.Is(err, errRunFailed) && strings.Contains(errOut.String(), "no sacl: key") {
		t.Fatalf("Run() refused a spec that already sets sacl: []: err=%v stderr=%q", err, errOut.String())
	}
}

// TestRunNoLongerRefusesKeepDACL is the flip side of the interim refusal
// TestRunRefusesKeepDACLUntilApplyLands used to pin: now that applyKeepDACL
// exists (plan v3 commit 4), a rule with sacl: and no acl: must load and run
// instead of being refused before the walk. The kernel transport's tmpdir
// returns ENOTSUP for the nfs4_acl xattr (no real NFSv4 ACL support on a local
// filesystem), so the run still fails overall once it reaches the per-object
// GetACL -- but it must fail there, as an ordinary per-object error, never at
// the old guard.
func TestRunNoLongerRefusesKeepDACL(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t,
		"protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Sacl: true,
		// The flattening ack is what this test is not about; see
		// TestRunKeepDACLApplyNeedsFlatteningAck.
		AcceptDACLFlattening: true,
		Root:                 root,
		SpecPath:             specPath,
		Spec:                 loadedSpec,
		Transport:            "kernel",
		Workers:              1,
		BatchSize:            1,
		Apply:                true,
		Quiet:                true,
		ErrOut:               &errOut,
	}, &out)
	if strings.Contains(errOut.String(), "does not apply yet") {
		t.Fatalf("Run() still carries the removed interim refusal: err=%v stderr=%q", err, errOut.String())
	}
	// The spec is no longer turned away before anything runs: it reaches the
	// real preflight (apply.ProbePreflight -> applyKeepDACL's own GetACL),
	// which is where this environment actually fails -- a tmpdir's local
	// filesystem has no NFSv4 ACL support, so getxattr(system.nfs4_acl)
	// returns ENOTSUP. That is a world away from the old guard's refusal
	// before the transport was even used, and is what this test is pinning:
	// the spec got as far as a real ACL read being attempted. A true
	// end-to-end success (enumeration, a real write, --compare skipping a
	// second run) needs a server that actually implements system.nfs4_acl,
	// which is exactly what the apply-level tests in internal/apply cover
	// instead, with a fake transport.
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want errRunFailed (ENOTSUP on the tmpdir's nfs4_acl xattr)", err)
	}
	// Darwin's local filesystems do support xattrs, so there the same read
	// fails ENOATTR ("attribute not found") rather than ENOTSUP.
	if !strings.Contains(errOut.String(), "not supported") && !strings.Contains(errOut.String(), "attribute not found") {
		t.Fatalf("stderr = %q, want it to show the preflight actually attempted a real ACL read (ENOTSUP), not an early refusal", errOut.String())
	}
}

// TestRunKeepDACLDryRunReadsNothing pins review item 7: a dry run has no
// preflight to prove the audit bypass, and before Purity//FA 6.12.1 an ACL
// read without it empties an inheriting SACL, so a dry run of a DACL-keeping
// rule must not read at all -- no batch pre-fetch, no per-object GetACL. The
// tmpdir's nfs4_acl xattr returns ENOTSUP, so any read would surface as an
// error; a clean run with a WOULD line and no "batch GetACL" proves none
// happened. The dry run is the default here (no --apply), as it is for an
// operator who forgets the flag.
func TestRunKeepDACLDryRunReadsNothing(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t,
		"protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")

	var out, errOut, log strings.Builder
	ev := newEvidence(t, evidence.Options{})
	res, err := Run(context.Background(), Config{
		Sacl:      true,
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Quiet:     true,
		ErrOut:    &errOut,
		Log:       &log,
		Evidence:  ev,
	}, &out)
	audit := evidenceText(t, ev, res)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil (a dry run must not read, so ENOTSUP never surfaces); stderr=%q log=%q", err, errOut.String(), log.String())
	}
	if strings.Contains(log.String(), "batch GetACL") || strings.Contains(log.String(), "not supported") {
		t.Fatalf("log = %q, want no ACL read on a dry run", log.String())
	}
	if !strings.Contains(audit, "not read on a dry run") {
		t.Fatalf("evidence = %q, want the WOULD line for the file", audit)
	}
	if !strings.Contains(errOut.String(), "NOTE: dry run does not read") {
		t.Fatalf("stderr = %q, want the dry-run NOTE", errOut.String())
	}
}

// saclSpecDACL is a spec-DACL nfsv4 spec (acl: with sacl: together, so it is
// not DACL-keeping and passes the interim KeepDACL refusal). Its sacl: makes
// cfg.Spec.UsesSacl() true, which is all the tests below need: the real
// kernel transport's local filesystem has no NFSv4 ACL support, so the
// preflight write always fails with ENOTSUP, not an audit-specific status --
// these tests pin that the NOTE prints and that the probe actually runs, not
// the specific sentinel apply's own tests already cover with a fake
// transport.
const saclSpecDACL = "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n"

// TestRunPrintsTheAuditPolicyNoteWhenSaclIsUsed pins the unconditional NOTE:
// it must print on an apply run with sacl: regardless of what the preflight
// below it finds.
func TestRunPrintsTheAuditPolicyNoteWhenSaclIsUsed(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t, saclSpecDACL)

	var out, errOut strings.Builder
	Run(context.Background(), Config{
		Sacl:      true,
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if !strings.Contains(errOut.String(), "NOTE: sacl:") {
		t.Errorf("stderr = %q, want the audit-policy NOTE", errOut.String())
	}
}

// TestRunPrintsNoAuditNoteWithoutSacl pins the other half: a spec with no
// sacl: at all must not print the NOTE, so an ordinary posix/nfsv4 run's
// output is unchanged.
func TestRunPrintsNoAuditNoteWithoutSacl(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t, posixSpec)

	var out, errOut strings.Builder
	Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if strings.Contains(errOut.String(), "NOTE: sacl:") {
		t.Errorf("stderr = %q, want no audit-policy NOTE for a spec with no sacl:", errOut.String())
	}
}

// TestValidateRunsThePreflightWhenSaclIsUsed is the regression test for the
// gap commit 2 closes: before it, --validate never touched ProbePreflight at
// all, so an identity lacking the array's audit bypass would validate a
// sacl: spec as if every object matched. The real kernel transport's local
// filesystem has no NFSv4 ACL support, so the preflight write here fails with
// ENOTSUP -- the point of this test is that --validate now surfaces that
// failure instead of silently proceeding to enumerate.
func TestValidateRunsThePreflightWhenSaclIsUsed(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t, saclSpecDACL)

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Sacl:      true,
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Validate:  true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want errRunFailed -- --validate must run the preflight for a sacl: spec", err)
	}
	if !strings.Contains(errOut.String(), "preflight probe failed") {
		t.Errorf("stderr = %q, want the preflight failure reported", errOut.String())
	}
}

// TestValidateRunsThePreflightForEmptySacl: a spec whose only sacl: key is
// sacl: [] must also prove the bypass before --validate reads every object.
func TestValidateRunsThePreflightForEmptySacl(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t, "protocol: nfsv4\ndefault:\n  sacl: []\n")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Sacl:      true,
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Validate:  true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want errRunFailed -- --validate must run the preflight for a sacl: [] spec", err)
	}
	if !strings.Contains(errOut.String(), "preflight probe failed") {
		t.Errorf("stderr = %q, want the preflight failure reported", errOut.String())
	}
}

// TestValidateSkipsThePreflightWithoutSacl pins the non-regression: a spec
// with no sacl: must leave --validate exactly as it was, with no preflight
// probe at all (CLAUDE.md's "validate has ... no preflight probe" still holds
// for every spec this does not apply to).
func TestValidateSkipsThePreflightWithoutSacl(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Validate:  true,
		Quiet:     true,
		ErrOut:    &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil: a non-sacl spec must not run the preflight on --validate", err)
	}
}

func TestRunReturnsCanceledWhenContextIsAlreadyCanceled(t *testing.T) {
	root := t.TempDir()
	specPath := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specPath, []byte("protocol: posix\ndefault:\n  mode: \"0755\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loadedSpec, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := Run(ctx, Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(got, Result{}) {
		t.Fatalf("Run() result = %+v, want zero work before an already-canceled run", got)
	}
}

func TestRunDrainsAndJoinsAfterMidRunCancellation(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 500; i++ {
		path := filepath.Join(root, fmt.Sprintf("file-%04d.txt", i))
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	specPath := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specPath, []byte(posixSpec), 0600); err != nil {
		t.Fatal(err)
	}
	loadedSpec, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out strings.Builder
	done := make(chan struct{})
	var got Result
	var runErr error
	go func() {
		got, runErr = Run(ctx, Config{
			Root:      root,
			SpecPath:  specPath,
			Spec:      loadedSpec,
			Transport: "kernel",
			Workers:   4,
			BatchSize: 1,
			DryRun:    true,
			Quiet:     true,
			// The trigger has to be the evidence, not Log: since the log split,
			// Log carries only failures, and a clean dry run writes nothing to it,
			// so nothing would ever cancel the run. It is the shard Create, which
			// the writer calls on the first record, not the file's first Write:
			// records are buffered and flushed only when the queue runs dry, so a
			// fast run could submit all 500 before any Write and the cancel would
			// land after the work was done. Holding Create until the cancel lands,
			// with a one-record queue, stalls the producers mid-run.
			Evidence: newEvidence(t, evidence.Options{
				QueueRecords: 1,
				Create: func(string) (evidence.File, error) {
					cancel()
					<-ctx.Done()
					return evFile{io.Discard}, nil
				},
			}),
		}, &out)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after mid-run cancellation")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", runErr)
	}
	if got.Stats.Applied > got.Stats.Enumerated {
		t.Fatalf("Run() stats = %+v: applied must not exceed enumerated", got.Stats)
	}
	if got.Stats.Enumerated == 0 {
		t.Fatalf("Run() stats = %+v, want entries in flight before cancellation", got.Stats)
	}
}

func TestRunJoinsProgressReporterBeforeReturning(t *testing.T) {
	root := t.TempDir()
	specPath := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specPath, []byte("protocol: posix\ndefault:\n  mode: \"0755\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loadedSpec, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	writer := &returnTrackingWriter{}

	if _, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		DryRun:    true,
		ErrOut:    writer,
	}, writer); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	writer.returned.Store(true)
	time.Sleep(10 * time.Millisecond)
	if writer.afterReturn.Load() {
		t.Fatal("writer was used after Run returned")
	}
}

type returnTrackingWriter struct {
	returned    atomic.Bool
	afterReturn atomic.Bool
}

func (w *returnTrackingWriter) Write(p []byte) (int, error) {
	if w.returned.Load() {
		w.afterReturn.Store(true)
	}
	return len(p), nil
}

// TestRunFixesANonTraversableDirOnlyOnce is the throughput regression test for
// the double-processing bug: a directory whose initial readdir fails gets
// repaired by the prepass's Fix call (apply.FixDirPerms, which runs the real
// spec apply via ProcessPath) before the retry succeeds. Before the Entry.Fix
// plumbing, that directory's Entry still flowed to the worker unflagged, so
// ProcessPath ran on it a second time -- a second chmod with the same result,
// and a second audit line. This asserts both the stats and the audit log see
// the directory exactly once.
func TestRunFixesANonTraversableDirOnlyOnce(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0000); err != nil {
		t.Fatal(err)
	}
	// So the dir is actually fixed (and traversable) rather than just probed:
	// FixDirPerms's own ProcessPath call must change 0000 -> 0755 before the
	// retried readdir can succeed at all.
	specPath := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specPath, []byte(posixSpec), 0600); err != nil {
		t.Fatal(err)
	}
	loadedSpec, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	ev := newEvidence(t, evidence.Options{})
	got, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		Evidence:  ev,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got.Stats.Errors != 0 {
		t.Fatalf("Run() errors = %d, want 0 (evidence: %q)", got.Stats.Errors, evidenceText(t, ev, got))
	}

	info, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("sub mode = %04o, want 0755", info.Mode().Perm())
	}

	// Exactly one applied change for sub: the prepass's own Fix repaired it
	// (0000 -> 0755), and nothing should have touched it again afterward.
	if got.Stats.Applied != 1 {
		t.Fatalf("Stats.Applied = %d, want 1 (sub chmod'd exactly once)", got.Stats.Applied)
	}
	// And exactly one audit line should mention sub, not two: a worker
	// reprocessing it would produce a second "chmod 0755 .../sub" line with no
	// "[pre-pass]" prefix.
	subLines := 0
	auditLog := evidenceText(t, ev, got)
	for _, line := range strings.Split(auditLog, "\n") {
		if strings.Contains(line, sub) {
			subLines++
		}
	}
	if subLines != 1 {
		t.Fatalf("audit log has %d lines mentioning %s, want exactly 1:\n%s", subLines, sub, auditLog)
	}
}

func TestRunAppliesAWholeKernelTreeAndReturnsCounters(t *testing.T) {
	root := t.TempDir()
	// Ensure root is 0755 regardless of umask so the directory matches
	// the spec and is skipped (Applied=1 file, Skipped=1 dir).
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specPath, []byte(posixSpec), 0600); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	loadedSpec, err := spec.Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   2,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got.Stats.Applied != 1 || got.Stats.Skipped != 1 || got.Stats.Errors != 0 ||
		got.Stats.Enumerated != 2 || got.Stats.Symlinks != 0 || got.WalkErrors != 0 {
		t.Fatalf("Run() result = %+v, want one applied file, one skipped directory, two enumerated, and no errors", got)
	}
	if got.Elapsed <= 0 {
		t.Fatalf("Run() elapsed = %v, want positive", got.Elapsed)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rootInfo.Mode().Perm(), os.FileMode(0755); got != want {
		t.Fatalf("root mode = %04o, want %04o", got, want)
	}
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fileInfo.Mode().Perm(), os.FileMode(0644); got != want {
		t.Fatalf("file mode = %04o, want %04o", got, want)
	}
	if !strings.Contains(out.String(), "Complete:") {
		t.Fatalf("output missing existing summary: %q", out.String())
	}
}

// countObjects walks root and returns the total number of filesystem objects
// (directories + files + symlinks). It is deliberately independent of
// internal/walk so it can serve as an oracle for the enumeration count.
func countObjects(t *testing.T, root string) int64 {
	t.Helper()
	var n int64
	err := filepath.WalkDir(root, func(_ string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("countObjects: %v", err)
	}
	return n
}

func TestEnumeratedMatchesIndependentCount(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", i)), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := countObjects(t, root)

	specPath, loaded := writeSpec(t, posixSpec)
	var out strings.Builder
	got, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loaded,
		Transport: "kernel",
		Workers:   4,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got.Stats.Enumerated != want {
		t.Fatalf("Enumerated = %d, independent count = %d", got.Stats.Enumerated, want)
	}
}

func TestApplyThenValidateRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x", "y"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := countObjects(t, root)

	specPath, loaded := writeSpec(t, posixSpec)

	// Phase 1: apply.
	var applyOut strings.Builder
	applyResult, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loaded,
		Transport: "kernel",
		Workers:   4,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
	}, &applyOut)
	if err != nil {
		t.Fatalf("apply Run() error = %v", err)
	}
	if applyResult.Stats.Errors != 0 {
		t.Fatalf("apply had %d errors", applyResult.Stats.Errors)
	}
	if applyResult.Stats.Enumerated != want {
		t.Fatalf("apply Enumerated = %d, independent count = %d", applyResult.Stats.Enumerated, want)
	}

	// Phase 2: validate the same tree with the same spec.
	var valOut strings.Builder
	valResult, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loaded,
		Transport: "kernel",
		Workers:   4,
		BatchSize: 1,
		Validate:  true,
		Quiet:     true,
	}, &valOut)
	if err != nil {
		t.Fatalf("validate Run() error = %v", err)
	}
	if valResult.MismatchCount != 0 {
		t.Fatalf("validate found %d mismatches after a successful apply", valResult.MismatchCount)
	}
	if valResult.Stats.Enumerated != want {
		t.Fatalf("validate Enumerated = %d, independent count = %d", valResult.Stats.Enumerated, want)
	}
	if valResult.Stats.Enumerated != applyResult.Stats.Enumerated {
		t.Fatalf("apply enumerated %d but validate enumerated %d",
			applyResult.Stats.Enumerated, valResult.Stats.Enumerated)
	}
}

// The log split: --log is bounded by how much went wrong, --audit-log carries one
// line per object. The four tests below pin the routing, because the whole point
// of the change is that an operator who asks only for --log on a
// hundred-million-object tree does not get a multi-gigabyte file.

// errorSpec fixes modes like posixSpec but also demands root ownership, which a
// non-root run cannot set: every object produces an apply error, deterministically.
const errorSpec = "protocol: posix\ndefault:\n  mode: \"0755\"\nrules:\n" +
	"  - match:\n      type: directory\n    mode: \"0755\"\n    owner: \"0\"\n    group: \"0\"\n" +
	"  - match:\n      type: file\n    mode: \"0644\"\n    owner: \"0\"\n    group: \"0\"\n"

// logSplitTree is one directory, one file, one symlink -- enough to produce a
// per-object audit line of each shape the run can emit.
func logSplitTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	return root
}

func hasPerObjectLine(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimPrefix(line, "[pre-pass] ")
		switch {
		case strings.HasPrefix(line, "OK:"), strings.HasPrefix(line, "WOULD"),
			strings.HasPrefix(line, "FALLBACK:"), strings.HasPrefix(line, "SKIP:"):
			return true
		}
	}
	return false
}

// TestLogAloneRecordsNoPerObjectLines is the operator-safety assertion: a clean
// run configured with only Log must write nothing at all, because nothing failed.
func TestLogAloneRecordsNoPerObjectLines(t *testing.T) {
	root := logSplitTree(t)
	specPath, loadedSpec := writeSpec(t, posixSpec)
	var errLog, out, errOut strings.Builder
	if _, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 2, BatchSize: 1, Apply: true, Quiet: true,
		Log: &errLog, ErrOut: &errOut,
	}, &out); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if hasPerObjectLine(errLog.String()) {
		t.Errorf("--log contains per-object records:\n%s", errLog.String())
	}
	if errLog.Len() != 0 {
		t.Errorf("--log on a clean run = %q, want empty", errLog.String())
	}
}

// TestEvidenceCarriesPerObjectRecords is the other half: the evidence gets the
// records, and the error sink stays empty.
func TestEvidenceCarriesPerObjectRecords(t *testing.T) {
	root := logSplitTree(t)
	specPath, loadedSpec := writeSpec(t, posixSpec)
	var errLog, out, errOut strings.Builder
	ev := newEvidence(t, evidence.Options{})
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 2, BatchSize: 1, DryRun: true, Quiet: true,
		Log: &errLog, Evidence: ev, ErrOut: &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	audit := evidenceText(t, ev, res)
	if !hasPerObjectLine(audit) {
		t.Errorf("evidence has no per-object record:\n%s", audit)
	}
	if !strings.Contains(audit, "SKIP: symlink") {
		t.Errorf("evidence = %q, want the skipped symlink recorded", audit)
	}
	if errLog.Len() != 0 {
		t.Errorf("--log = %q, want empty: nothing failed", errLog.String())
	}
}

// TestErrorsReachBothSinks drives a run where every object fails: the
// failures land in Log, which carries nothing else, and in the evidence, which
// is the one ordered stream of everything the run did.
func TestErrorsReachBothSinks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chown to uid 0 would succeed")
	}
	root := logSplitTree(t)
	specPath, loadedSpec := writeSpec(t, errorSpec)
	var errLog, out, errOut strings.Builder
	ev := newEvidence(t, evidence.Options{})
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: loadedSpec, Transport: "kernel",
		Workers: 1, BatchSize: 1, Apply: true, SetOwner: true, Quiet: true,
		Log: &errLog, Evidence: ev, ErrOut: &errOut,
	}, &out)
	if err == nil {
		t.Fatal("Run() error = nil, want a failed run: every chown must fail")
	}
	if !strings.Contains(errLog.String(), "ERR:") || hasPerObjectLine(errLog.String()) {
		t.Errorf("--log = %q, want the apply errors and nothing else", errLog.String())
	}
	audit := evidenceText(t, ev, res)
	if !strings.Contains(audit, "ERR:") || !hasPerObjectLine(audit) {
		t.Errorf("evidence = %q, want error and per-object records together", audit)
	}
	// Apply errors are recorded, not lost: the evidence is still complete.
	if res.Evidence.Status != evidence.StatusComplete {
		t.Errorf("manifest = %+v, want complete", res.Evidence)
	}
}

func TestIsErrorLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"ERR: lstat /a/b failed", true},
		{"[pre-pass] ERR: /a/b: permission denied", true},
		{"OK: chmod 0644 /a/b", false},
		{"WOULD: setxattr nfs4_acl /a/b", false},
		{"[pre-pass] FALLBACK: chmod 755 /a/b: denied", false},
		{"SKIP: symlink /a/b", false},
		{"", false},
	} {
		if got := isErrorLine(tc.line); got != tc.want {
			t.Errorf("isErrorLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// The exclude counter must equal the number of objects taken out of scope, and
// an excluded directory counts once -- for itself -- because its subtree is
// never enumerated and there is nothing else to count.
func TestRunCountsAndPrunesExcludedObjects(t *testing.T) {
	root := t.TempDir()
	drop := filepath.Join(root, ".snapshot")
	if err := os.MkdirAll(filepath.Join(drop, "deep"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(drop, "a.txt"),
		filepath.Join(drop, "deep", "b.txt"),
		filepath.Join(root, "keep.txt"),
		filepath.Join(root, "scratch.tmp"),
	} {
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	specPath, loadedSpec := writeSpec(t, posixSpec+"exclude:\n  - .snapshot\n")

	var out, errOut strings.Builder
	got, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   2,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		Exclude:   []string{"*.tmp"},
		ErrOut:    &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run() error = %v, stderr=%q", err, errOut.String())
	}

	// The spec's pattern and the flag's pattern both apply: the union, not one
	// or the other.
	wantExcludes := []string{".snapshot", "*.tmp"}
	if !reflect.DeepEqual(got.Excludes, wantExcludes) {
		t.Errorf("Excludes = %v, want %v", got.Excludes, wantExcludes)
	}
	if got.Stats.Excluded != 2 {
		t.Errorf("Excluded = %d, want 2 (the pruned directory once, plus one .tmp file)", got.Stats.Excluded)
	}
	// Enumerated is the root plus keep.txt: everything under .snapshot was
	// pruned before it could be read.
	if got.Stats.Enumerated != 2 {
		t.Errorf("Enumerated = %d, want 2 (root and keep.txt); the excluded subtree leaked", got.Stats.Enumerated)
	}
	if !strings.Contains(out.String(), "Excluding: .snapshot *.tmp") {
		t.Errorf("stdout should echo the effective excludes; got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Excluded:   2") {
		t.Errorf("stdout counts block should report the exclusions; got:\n%s", out.String())
	}

	// Nothing in the excluded subtree may have been touched.
	st, err := os.Stat(filepath.Join(drop, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("excluded file mode = %v, want 0600 unchanged", st.Mode().Perm())
	}
}

func TestRunRejectsMalformedExcludePattern(t *testing.T) {
	root := t.TempDir()
	specPath, loadedSpec := writeSpec(t, posixSpec)
	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:      root,
		SpecPath:  specPath,
		Spec:      loadedSpec,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		Apply:     true,
		Quiet:     true,
		Exclude:   []string{"["},
		ErrOut:    &errOut,
	}, &out)
	if err == nil {
		t.Fatal("Run() error = nil, want a refusal of the malformed pattern")
	}
	if !strings.Contains(errOut.String(), "invalid glob pattern") {
		t.Errorf("stderr = %q, want the pattern named", errOut.String())
	}
}

// specWithOwner builds the smallest posix spec that reaches identity
// pre-resolution: a default rule naming an owner. Offline -- no mount, no array.
func specWithOwner(t *testing.T, owner string) (string, *spec.Spec) {
	t.Helper()
	return writeSpec(t, "protocol: posix\ndefault:\n  mode: \"0755\"\n  owner: \""+owner+"\"\n")
}

// offlineConfig is a Run configuration over a tmpdir with the kernel transport,
// dry-run, and no checkpoint: enough to reach pre-resolution and stop soon after.
func offlineConfig(t *testing.T, specPath string, s *spec.Spec) Config {
	t.Helper()
	return Config{
		Root:      t.TempDir(),
		SpecPath:  specPath,
		Spec:      s,
		Transport: "kernel",
		Workers:   1,
		BatchSize: 1,
		DryRun:    true,
		Quiet:     true,
	}
}

// On the kernel transport the local directory IS the authority the repair will
// use, so an unresolvable principal is a typo caught before a million-object
// run -- which is the entire reason the check exists.
func TestUnresolvablePrincipalIsFatalWhenLocalIdentityIsAuthoritative(t *testing.T) {
	specPath, s := specWithOwner(t, "definitely-not-a-real-user-9f3a2b")

	var out, errOut strings.Builder
	cfg := offlineConfig(t, specPath, s)
	cfg.LocalIdentityAuthoritative = true
	cfg.ErrOut = &errOut

	if _, err := Run(context.Background(), cfg, &out); err == nil {
		t.Fatal("Run succeeded with an unresolvable owner; the check must be fatal here")
	}
	if got := errOut.String(); !strings.Contains(got, "identity pre-resolution failed") {
		t.Fatalf("stderr = %q, want the pre-resolution failure", got)
	}
}

// Off the kernel transport the ARRAY is the authority and a local miss proves
// nothing. The check degrades to a warning rather than to silence, because a
// genuine typo is still worth saying out loud.
func TestUnresolvablePrincipalIsAdvisoryWhenLocalIdentityIsNot(t *testing.T) {
	specPath, s := specWithOwner(t, "definitely-not-a-real-user-9f3a2b")

	var out, errOut strings.Builder
	cfg := offlineConfig(t, specPath, s)
	cfg.LocalIdentityAuthoritative = false
	cfg.ErrOut = &errOut

	if _, err := Run(context.Background(), cfg, &out); err != nil {
		t.Fatalf("Run failed on an unresolvable owner that only the array can resolve: %v", err)
	}
	got := errOut.String()
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "definitely-not-a-real-user-9f3a2b") {
		t.Fatalf("stderr = %q, want a warning naming the principal", got)
	}
	if strings.Contains(got, "ERROR") {
		t.Fatalf("stderr = %q, want no error line", got)
	}
}

// The root-squash fact moved out of the startup warnings and into this hint,
// which fires only after something has already failed. uid 0 is an ordinary way
// to run against an export that does not squash, so saying it up front nags a
// supported Linux configuration; saying it beside a failure explains one.
func TestRootSquashHintExplainsAFailedRootRun(t *testing.T) {
	var errOut bytes.Buffer
	rootSquashHint(&errOut, Config{Transport: "userspace", Auth: &nfs41.AuthSys{UID: 0}})
	got := errOut.String()
	if !strings.Contains(got, "squash") {
		t.Fatalf("output = %q, want the root-squash explanation", got)
	}
	if !strings.Contains(got, "--auth-uid") {
		t.Fatalf("output = %q, want the fix named", got)
	}
}

// Any other uid gets nothing: the hint explains one specific cause, and
// attaching it to every failure would make it noise on the failures it does not
// explain.
func TestRootSquashHintIsSilentForANonRootCredential(t *testing.T) {
	var errOut bytes.Buffer
	rootSquashHint(&errOut, Config{Transport: "userspace", Auth: &nfs41.AuthSys{UID: 501}})
	if got := errOut.String(); got != "" {
		t.Fatalf("output = %q, want none for uid 501", got)
	}
}

// The kernel transport authenticates through the mount and never puts AUTH_SYS
// on the wire, so a uid-0 kernel failure has nothing to do with squashing this
// credential.
func TestRootSquashHintIsSilentOnTheKernelTransport(t *testing.T) {
	var errOut bytes.Buffer
	rootSquashHint(&errOut, Config{Transport: "kernel", Auth: &nfs41.AuthSys{UID: 0}})
	if got := errOut.String(); got != "" {
		t.Fatalf("output = %q, want none: the kernel transport sends no AUTH_SYS", got)
	}
}

// The default invocation -- no --apply, no --dry-run -- is a dry run, and the
// tool labels it dry-run=true in its own run detail. It must be refused with a
// checkpoint for exactly the reason the refusal states: DirApplyDone and
// EntryDone are not gated on DryRun, so a run that writes nothing still records
// every directory complete, and a later --apply --resume skips the whole tree
// and reports success over an unrepaired filesystem.
func TestCheckpointRefusesTheImplicitDryRun(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	specPath, loadedSpec := writeSpec(t, posixSpec)
	ckptPath := filepath.Join(t.TempDir(), "ckpt")

	var out, errOut strings.Builder
	_, err := Run(context.Background(), Config{
		Root:           root,
		SpecPath:       specPath,
		Spec:           loadedSpec,
		Transport:      "kernel",
		Workers:        1,
		BatchSize:      1,
		Quiet:          true,
		CheckpointPath: ckptPath,
		ErrOut:         &errOut,
	}, &out)
	if !errors.Is(err, errRunFailed) {
		t.Fatalf("Run() error = %v, want the checkpoint refusal", err)
	}
	if got := errOut.String(); !strings.Contains(got, "--checkpoint cannot be used") {
		t.Fatalf("stderr = %q, want the checkpoint refusal", got)
	}
	if _, err := os.Stat(ckptPath); err == nil {
		t.Fatal("a refused run wrote a checkpoint; a later --resume would skip the tree")
	}
}
