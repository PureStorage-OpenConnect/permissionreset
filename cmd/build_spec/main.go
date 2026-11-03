// Command build-spec reads NFSv4 ACLs from two exemplar objects (a directory
// and a regular file) and emits a validated permissionreset spec YAML.
//
// Usage:
//
//	build-spec [flags] DIRECTORY FILE
//
// On Linux the kernel NFS client transport is the default. On macOS and Windows
// the userspace transport speaks NFSv4.1 directly and requires --server and
// --export. Both positional arguments are paths to existing objects whose ACLs
// define the template rules the generated spec will enforce.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/saclplan"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/session"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// deps holds the injectable dependencies so tests need no mount or real
// kernel transport.
type deps struct {
	// newKernel constructs a speccapture.Reader backed by the kernel transport.
	// root is the NFS mount point.
	newKernel func(root string) (speccapture.Reader, error)

	// openMounts returns a readable /proc/mounts (or equivalent). Callers must
	// close the returned ReadCloser.
	openMounts func() (io.ReadCloser, error)

	// resolveMount wraps tuning.ResolveMount. Separated so tests can inject a
	// resolver that doesn't parse /proc/mounts.
	resolveMount func(target string, r io.Reader) (tuning.Mount, error)

	// newUserspace opens the userspace NFSv4.1 connection. It returns the
	// Reader for Capture, the ReplayVerifier for --verify-write, and a closer
	// that sends DESTROY_SESSION. Tests inject fakes so no network is required.
	newUserspace func(ctx context.Context, cfg nfs41.Config) (speccapture.Reader, speccapture.ReplayVerifier, func() error, error)
}

func productionDeps() deps {
	return deps{
		newKernel:    newKernelFromMount,
		openMounts:   func() (io.ReadCloser, error) { return os.Open("/proc/mounts") },
		resolveMount: tuning.ResolveMount,
		newUserspace: session.NewUserspace,
	}
}

type buildSpecFlags struct {
	output      *string
	transportFl *string
	server      *string
	export      *string
	verifyWrite *string
	rpcTimeout  *time.Duration
	retryBudget *int
	retryBase   *time.Duration
	showVersion *bool
	withDACL    *bool
	probeDir    *string
	acceptRead  *bool
	saclPlan    *string
	auth        *cmdflags.AuthFlags
	gate        *cmdflags.Gate
}

func registerFlags(fs *flag.FlagSet, errOut io.Writer) (*flag.FlagSet, *buildSpecFlags) {
	fs.SetOutput(errOut)
	g := &cmdflags.Gate{OS: caps.OS, Arch: runtime.GOARCH}
	f := &buildSpecFlags{gate: g}

	f.output = fs.String("output", "", "output path for the spec YAML, or - for stdout (required)")
	// --transport is registered everywhere; only the value "kernel" is gated.
	f.transportFl = fs.String("transport", defaultTransport(), "transport: kernel or userspace")
	g.Value("transport", "kernel", cmdflags.KernelTransport(caps))
	f.server = fs.String("server", "", "NFS server HOST[:PORT] (required for userspace)")
	f.export = fs.String("export", "", "export path on the server (required for userspace)")
	// --verify-write: flag is registered; implementation seam for Task 5.
	f.verifyWrite = fs.String("verify-write", "", "scratch directory for write-round-trip verification (opt-in)")
	f.rpcTimeout = fs.Duration("rpc-timeout", 30*time.Second, "per-COMPOUND deadline (userspace only)")
	f.retryBudget = fs.Int("retry-budget", 5, "attempts before an object is failed (userspace only)")
	f.retryBase = fs.Duration("retry-base-delay", 100*time.Millisecond, "exponential backoff base (userspace only)")
	f.withDACL = fs.Bool("with-dacl", false, "when the exemplars carry audit (U) ACEs, also write their DACLs as acl: -- "+
		"by default such a spec keeps each object's own DACL and replaces only its SACL")
	f.probeDir = fs.String("probe-dir", "", "directory on the same mount (userspace: server path inside the export) where a "+
		"disposable probe proves the audit bypass before the exemplars are read; defaults to the --verify-write directory")
	f.acceptRead = fs.Bool("accept-unproven-read", false, "read the exemplar ACLs with no audit-bypass proof; on an array "+
		"where an unprivileged read empties inherited auditing, this can change the exemplars")
	f.saclPlan = fs.String("sacl-plan", "", "print the SACL plan for this permissionreset spec as JSON on stdout and exit, for "+
		"tools/set-saclonly/Set-SaclOnly.ps1; reads only the spec and takes no other flag or argument")
	f.showVersion = fs.Bool("version", false, "print version and exit")
	f.auth = cmdflags.RegisterAuth(fs, func(s string) string { return s + " (--transport=userspace only)" })

	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: build-spec [flags] DIRECTORY FILE\n       build-spec --sacl-plan SPEC.yaml")
		fs.VisitAll(func(ff *flag.Flag) {
			if ff.Usage == "" {
				return // hidden flag
			}
			fmt.Fprintf(errOut, "  -%s\n    \t%s", ff.Name, ff.Usage)
			if ff.DefValue != "" && ff.DefValue != "false" && ff.DefValue != "0" && ff.DefValue != "0s" {
				fmt.Fprintf(errOut, " (default %s)", ff.DefValue)
			}
			fmt.Fprintln(errOut)
		})
	}
	return fs, f
}

// run is the thin, testable entry point. It returns an OS exit code.
// stdout receives only YAML (when --output -); all status goes to stderr.
func run(args []string, stdout, stderr io.Writer, d deps) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return 1
	}

	fs, f := registerFlags(flag.NewFlagSet("build-spec", flag.ContinueOnError), stderr)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *f.showVersion {
		fmt.Fprintf(stderr, "build-spec %s (%s) built %s\n", version, commit, date)
		return 0
	}

	explicit := tuning.Explicit(fs)

	if explicit["sacl-plan"] {
		return runSaclPlan(*f.saclPlan, explicit, fs.Args(), stdout, stderr)
	}

	// Gate check: refuses --transport=kernel on non-kernel builds.
	if f.gate.Reject(explicit, map[string]string{"transport": *f.transportFl}, stderr) {
		return 1
	}

	if *f.output == "" {
		return fail("--output is required; use - to write YAML to stdout")
	}

	if fs.NArg() != 2 {
		return fail("expected DIRECTORY FILE positional arguments, got %d", fs.NArg())
	}

	// Resolve and emit auth warnings for the current transport, mirroring sweep.
	authSys, authWarnings, authErr := f.auth.Resolve(explicit, *f.transportFl)
	if authErr != nil {
		return fail("%v", authErr)
	}
	for _, w := range authWarnings {
		fmt.Fprintln(stderr, w)
	}

	opts := speccapture.Options{WithDACL: *f.withDACL, ProbeDir: *f.probeDir, AcceptUnprovenRead: *f.acceptRead}
	switch *f.transportFl {
	case "kernel":
		return runKernel(fs.Arg(0), fs.Arg(1), *f.output, *f.verifyWrite, opts, d, stdout, stderr)
	case "userspace":
		return runUserspace(fs.Arg(0), fs.Arg(1), *f.output, *f.server, *f.export, *f.verifyWrite, opts,
			authSys, *f.rpcTimeout, *f.retryBudget, *f.retryBase, d, stdout, stderr)
	default:
		return fail("unknown transport %q; use kernel or userspace", *f.transportFl)
	}
}

// runKernel resolves both positionals to absolute local paths, verifies they
// live on the same NFSv4.1 mount, and calls speccapture.Capture via the kernel
// transport.
func runKernel(dirArg, fileArg, outputPath, verifyWrite string, opts speccapture.Options, d deps, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return 1
	}

	dirAbs, err := filepath.Abs(dirArg)
	if err != nil {
		return fail("resolve directory path %q: %v", dirArg, err)
	}
	fileAbs, err := filepath.Abs(fileArg)
	if err != nil {
		return fail("resolve file path %q: %v", fileArg, err)
	}

	// Read mount table once; reuse via bytes.NewReader for each call.
	mf, err := d.openMounts()
	if err != nil {
		return fail("open mount table: %v", err)
	}
	mountData, readErr := io.ReadAll(mf)
	closeErr := mf.Close()
	if readErr != nil {
		return fail("read mount table: %v", readErr)
	}
	if closeErr != nil {
		return fail("close mount table: %v", closeErr)
	}

	dirMount, err := d.resolveMount(dirAbs, bytes.NewReader(mountData))
	if err != nil {
		return fail("directory %q: %v", dirAbs, err)
	}
	fileMount, err := d.resolveMount(fileAbs, bytes.NewReader(mountData))
	if err != nil {
		return fail("file %q: %v", fileAbs, err)
	}

	if dirMount.MountPoint != fileMount.MountPoint {
		return fail("DIRECTORY and FILE must be on the same NFS mount\n"+
			"  directory: %s (mount %s)\n"+
			"  file:      %s (mount %s)",
			dirAbs, dirMount.MountPoint, fileAbs, fileMount.MountPoint)
	}

	if err := checkNFS41(dirMount.MountPoint, bytes.NewReader(mountData)); err != nil {
		return fail("%v", err)
	}

	reader, err := d.newKernel(dirMount.MountPoint)
	if err != nil {
		return fail("init kernel transport: %v", err)
	}
	if closer, ok := reader.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	if opts.ProbeDir == "" {
		opts.ProbeDir = verifyWrite
	}
	if opts.ProbeDir != "" {
		probeAbs, err := filepath.Abs(opts.ProbeDir)
		if err != nil {
			return fail("resolve probe directory %q: %v", opts.ProbeDir, err)
		}
		probeMount, err := d.resolveMount(probeAbs, bytes.NewReader(mountData))
		if err != nil {
			return fail("resolve mount for probe directory %q: %v", opts.ProbeDir, err)
		}
		if probeMount.MountPoint != dirMount.MountPoint {
			return fail("probe directory %q is on mount %q, but exemplars are on %q; "+
				"use a directory under the same NFS mount", opts.ProbeDir, probeMount.MountPoint, dirMount.MountPoint)
		}
		opts.ProbeDir = probeAbs
	}

	res, err := speccapture.CaptureWithOptions(reader, transport.Ref{Path: dirAbs}, transport.Ref{Path: fileAbs}, opts)
	if err != nil {
		return captureFailed(err, stderr)
	}

	if verifyWrite != "" {
		scratchAbs, err := filepath.Abs(verifyWrite)
		if err != nil {
			return fail("resolve --verify-write path %q: %v", verifyWrite, err)
		}
		scratchMount, err := d.resolveMount(scratchAbs, bytes.NewReader(mountData))
		if err != nil {
			return fail("resolve mount for --verify-write scratch %q: %v", verifyWrite, err)
		}
		if scratchMount.MountPoint != dirMount.MountPoint {
			return fail("--verify-write scratch %q is on mount %q, but exemplars are on %q; "+
				"use a directory under the same NFS mount",
				verifyWrite, scratchMount.MountPoint, dirMount.MountPoint)
		}
		verified, verifyErr := speccapture.Verify(
			newKernelVerifier(),
			transport.Ref{Path: scratchAbs},
			transport.Ref{Path: dirAbs},
			transport.Ref{Path: fileAbs},
			res,
		)
		if verifyErr != nil {
			fmt.Fprintf(stderr, "error: --verify-write: %v\n", verifyErr)
			return 1
		}
		res = verified
	}

	printResult(stderr, res)
	return writeOutput(outputPath, res.YAML, stdout, stderr)
}

// captureFailed reports a capture error, with what to do next when the
// capture refused to read the exemplars without a proven audit bypass.
func captureFailed(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "error: capture: %v\n", err)
	switch {
	case errors.Is(err, speccapture.ErrUnprovenRead):
		fmt.Fprintln(stderr, "hint: pass --probe-dir DIR (a directory on the same mount where a disposable object "+
			"can be created and removed), or --accept-unproven-read to read without the proof.")
		fmt.Fprintln(stderr, "Nothing was read.")
	case errors.Is(err, auditproof.ErrAuditPrivilege):
		fmt.Fprintln(stderr, "hint: reading the exemplars safely needs the array's audit bypass: root over AUTH_SYS "+
			"with root squash off, or an identity the array grants the bypass directly. Nothing was read.")
	case errors.Is(err, auditproof.ErrAuditNotRetained):
		fmt.Fprintln(stderr, "hint: the array accepted the probe's audit ACE but did not keep it. Nothing was read.")
	}
	return 1
}

// printResult writes the capture notes and the identity summary to stderr.
func printResult(stderr io.Writer, res *speccapture.Result) {
	for _, n := range res.Notes {
		fmt.Fprintln(stderr, "NOTE: "+n)
	}
	fmt.Fprint(stderr, res.Identity.String())
}

// validateUserspaceArgs validates --server, --export, and both positional
// server-side paths. All paths use path (not filepath) so forward slashes are
// enforced on every platform, including Windows.
func validateUserspaceArgs(dirArg, fileArg, server, export string) error {
	if server == "" {
		return fmt.Errorf("--server is required for --transport=userspace")
	}
	if export == "" {
		return fmt.Errorf("--export is required for --transport=userspace")
	}
	if err := validateServerPath(dirArg, export, "directory"); err != nil {
		return err
	}
	return validateServerPath(fileArg, export, "file")
}

// validateServerPath checks that p is an absolute forward-slash path strictly
// inside export with no ".." escape.
func validateServerPath(p, export, label string) error {
	if strings.Contains(p, `\`) {
		hint := strings.ReplaceAll(p, `\`, "/")
		return fmt.Errorf("%s path %q contains backslashes; use forward slashes on all platforms (e.g. %s)",
			label, p, hint)
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("%s path %q must be an absolute path (start with /)", label, p)
	}
	clean := path.Clean(p)
	exportClean := path.Clean(export)
	if clean == exportClean {
		return fmt.Errorf("%s path %q is the export root %q; give a path inside the export",
			label, p, export)
	}
	if !strings.HasPrefix(clean, exportClean+"/") {
		return fmt.Errorf("%s path %q is not inside export %q", label, p, export)
	}
	// path.Clean collapses "..", so if clean differs from the logical join
	// then there was an upward escape.
	rel := strings.TrimPrefix(clean, exportClean+"/")
	if strings.Contains(rel, "..") || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("%s path %q contains a '..' component that escapes the export", label, p)
	}
	return nil
}

// runUserspace validates arguments, opens one NFSv4.1 session rooted at the
// directory exemplar, reads both ACLs, and writes the validated spec YAML.
func runUserspace(dirArg, fileArg, outputPath, server, export, verifyWrite string, opts speccapture.Options,
	authSys *nfs41.AuthSys, rpcTimeout time.Duration, retryBudget int, retryBase time.Duration,
	d deps, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return 1
	}

	if err := validateUserspaceArgs(dirArg, fileArg, server, export); err != nil {
		return fail("%v", err)
	}
	if opts.ProbeDir == "" {
		opts.ProbeDir = verifyWrite
	}
	if opts.ProbeDir != "" {
		if err := validateServerPath(opts.ProbeDir, export, "probe directory"); err != nil {
			return fail("%v", err)
		}
	}

	ctx := context.Background()
	reader, verifier, closer, err := d.newUserspace(ctx, nfs41.Config{
		Server:         server,
		Export:         export,
		Target:         dirArg,
		RPCTimeout:     rpcTimeout,
		RetryBudget:    retryBudget,
		RetryBaseDelay: retryBase,
		Auth:           authSys,
		Log:            func(msg string) { fmt.Fprintln(stderr, msg) },
	})
	if err != nil {
		if errors.Is(err, nfs41.ErrNotPureServer) || errors.Is(err, nfs41.ErrFlashArrayNotSupported) {
			fmt.Fprintln(stderr, "error: "+err.Error())
		} else {
			fmt.Fprintf(stderr, "error: connect to %s%s: %v\n", server, export, err)
			fmt.Fprintln(stderr, "hint: build-spec uses AUTH_SYS (sec=sys) only; "+
				"if this export requires Kerberos, use --transport=kernel with a Kerberos-mounted NFS share")
		}
		return 1
	}
	defer func() {
		if err := closer(); err != nil {
			fmt.Fprintf(stderr, "WARNING: close transport: %v (the session expires server-side, "+
				"so a failed DESTROY_SESSION costs nothing)\n", err)
		}
	}()

	dirRef := transport.Ref{Path: dirArg}
	fileRef := transport.Ref{Path: fileArg}

	res, err := speccapture.CaptureWithOptions(reader, dirRef, fileRef, opts)
	if err != nil {
		return captureFailed(err, stderr)
	}

	if verifyWrite != "" {
		// Validate scratch is inside the same export and is a well-formed server path.
		if err := validateServerPath(verifyWrite, export, "scratch"); err != nil {
			return fail("--verify-write: %v", err)
		}
		scratchRef := transport.Ref{Path: verifyWrite}
		verified, verifyErr := speccapture.Verify(verifier, scratchRef, dirRef, fileRef, res)
		if verifyErr != nil {
			fmt.Fprintf(stderr, "error: --verify-write: %v\n", verifyErr)
			return 1
		}
		res = verified
	}

	printResult(stderr, res)
	return writeOutput(outputPath, res.YAML, stdout, stderr)
}

// checkNFS41 scans the mount table for mountPoint and verifies the mount's
// options advertise NFSv4.1 via "vers=4.1" or "minorversion=1".
func checkNFS41(mountPoint string, mounts io.Reader) error {
	scanner := bufio.NewScanner(mounts)
	var lastOpts string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[2] != "nfs" && fields[2] != "nfs4" {
			continue
		}
		if fields[1] != mountPoint {
			continue
		}
		if isNFS41Options(fields[3]) {
			return nil
		}
		lastOpts = fields[3]
	}
	if lastOpts != "" {
		return fmt.Errorf("mount %s is not NFSv4.1: options %q do not contain vers=4.1 or minorversion=1\n"+
			"  remount with vers=4.1, or use --transport=userspace which speaks NFSv4.1 directly",
			mountPoint, lastOpts)
	}
	return fmt.Errorf("mount point %q not found in mount table", mountPoint)
}

// isNFS41Options reports whether the comma-separated options string contains a
// token advertising NFSv4 minor version 1.
func isNFS41Options(opts string) bool {
	for _, opt := range strings.Split(opts, ",") {
		switch strings.TrimSpace(opt) {
		case "vers=4.1", "minorversion=1":
			return true
		}
	}
	return false
}

// writeOutput writes yaml to outputPath, or to stdout when outputPath is "-".
// File output uses O_CREATE|O_EXCL — an existing file is refused, never
// overwritten. The absolute local output path is printed to stderr on success.
func writeOutput(outputPath string, yaml []byte, stdout, stderr io.Writer) int {
	if outputPath == "-" {
		if _, err := stdout.Write(yaml); err != nil {
			fmt.Fprintf(stderr, "error: write stdout: %v\n", err)
			return 1
		}
		return 0
	}

	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			fmt.Fprintf(stderr, "error: output file %s already exists; "+
				"remove it first (build-spec never overwrites an existing spec)\n", outputPath)
		} else {
			fmt.Fprintf(stderr, "error: create %s: %v\n", outputPath, err)
		}
		return 1
	}

	_, writeErr := f.Write(yaml)
	closeErr := f.Close()
	if writeErr != nil {
		fmt.Fprintf(stderr, "error: write %s: %v\n", outputPath, writeErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "error: close %s: %v\n", outputPath, closeErr)
		return 1
	}

	abs, err := filepath.Abs(outputPath)
	if err != nil {
		abs = outputPath
	}
	fmt.Fprintf(stderr, "wrote %s\n", abs)
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, productionDeps()))
}

// runSaclPlan is the --sacl-plan mode: load specPath with full validation and
// print saclplan's JSON for it. It is a mode of its own, so any other flag or a
// positional argument is refused rather than silently ignored -- a capture
// flag next to it would read as though a capture ran.
func runSaclPlan(specPath string, explicit map[string]bool, args []string, stdout, stderr io.Writer) int {
	var others []string
	for name := range explicit {
		if name != "sacl-plan" {
			others = append(others, "--"+name)
		}
	}
	if len(others) > 0 {
		sort.Strings(others)
		fmt.Fprintf(stderr, "error: --sacl-plan is a mode of its own and cannot be combined with %s\n",
			strings.Join(others, ", "))
		return 1
	}
	if len(args) > 0 {
		fmt.Fprintf(stderr, "error: --sacl-plan takes no positional arguments, got %d (%s)\n",
			len(args), strings.Join(args, " "))
		return 1
	}
	if specPath == "" {
		fmt.Fprintln(stderr, "error: --sacl-plan needs the path of a permissionreset spec")
		return 1
	}

	s, err := spec.Load(specPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	plan, err := saclplan.Build(s, specPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	out, err := plan.Marshal()
	if err != nil {
		fmt.Fprintf(stderr, "error: encode plan: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "error: write stdout: %v\n", err)
		return 1
	}
	return 0
}
