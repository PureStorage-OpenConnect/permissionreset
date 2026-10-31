package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	runpkg "github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/signals"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/summary"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
	"golang.org/x/sys/unix"
)

const (
	maxTunedSlots             = tuning.MaxSlots
	maxTunedConnections       = tuning.MaxConnections
	maxTunedWorkers           = tuning.MaxWorkers
	maxTunedBatchSize         = tuning.MaxBatchSize
	maxTunedMaxOpsPerCompound = tuning.MaxOpsPerCompound
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"

	runCommand     = runpkg.Run
	executablePath = os.Executable
	openMounts     = func() (io.ReadCloser, error) { return os.Open("/proc/mounts") }
	hostname       = os.Hostname
	getRlimit      = unix.Getrlimit
)

// writeHeapProfile writes a live-heap profile to path, through a temporary file
// so a reader never sees a half-written profile and a kill mid-write cannot
// destroy the previous good one.
//
// The runtime.GC() call is what makes the numbers mean "reachable" rather than
// "allocated and not yet swept", which is the distinction the whole OOM
// investigation turns on. It costs a GC cycle per interval, which is affordable
// at the 30s default and is why this is opt-in rather than always on.
//
// Every failure is a warning and nothing more: a profile is a diagnostic, and
// losing one must never take down a repair that is otherwise succeeding.
func writeHeapProfile(path string, errOut io.Writer) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		fmt.Fprintf(errOut, "WARN: create heap profile %s: %v\n", tmp, err)
		return
	}
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(errOut, "WARN: write heap profile: %v\n", err)
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(errOut, "WARN: close heap profile: %v\n", err)
		return
	}
	// Rename last, so the file at path is always a complete profile.
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(errOut, "WARN: rename heap profile: %v\n", err)
	}
}

// run holds what used to be main. main must not be the function that exits:
// os.Exit skips deferred calls. internal/run closes its transport and checkpoint
// before Run returns, and this function closes the log and CPU profile after that.
// Returning a code and exiting in one place is what makes those defers run on
// every path, including --validate and every error exit.
func run() int {
	return runWithFlagSet(os.Args[1:], os.Stdout, os.Stderr)
}

// flags holds every flag pointer registerFlags produces, plus the gate that
// knows which of them this build refuses. It exists so the flag surface can be
// registered without running the command -- TestEveryFlagIsClassified walks it
// -- while runWithFlagSet still reaches each value by name.
type flags struct {
	gate *cmdflags.Gate

	specPath           *string
	workers            *int
	dryRun             *bool
	validate           *bool
	logPath            *string
	auditLogPath       *string
	evidenceDir        *string
	evidenceProfile    *string
	evidenceShardMB    *int
	evidenceGzip       *bool
	usePfindFlag       *bool
	noPfind            *bool
	compare            *bool
	ckptPath           *string
	resume             *bool
	quiet              *bool
	jsonSummary        *string
	setOwner           *bool
	batchSize          *int
	applyFlag          *bool
	skipIdentityCheck  *bool
	excludes           *stringList
	oneFilesystem      *bool
	showVersion        *bool
	transportName      *string
	server             *string
	export             *string
	connections        *int
	slots              *int
	maxOpsPerCompound  *int
	rpcTimeout         *time.Duration
	retryBudget        *int
	retryBaseDelay     *time.Duration
	unsafeAllowNonPure *bool
	supportBundle      *string
	noRedact           *bool
	cpuProfile         *string
	memProfile         *string
	memProfileInterval *time.Duration
	rpcStats           *bool
	authFlags          *cmdflags.AuthFlags
	sacl               *bool
	acceptFlatten      *bool
	allowHighIDs       *bool
	partitions         *string
	partitionOnly      *stringList
}

type buildSummaryOpts struct {
	target        string
	transportName string
	server        string
	export        string
	specPath      string
	specDigest    string
	batchSize     int
	connections   int
	usePfind      bool
	oneFilesystem bool
	ckptPath      string
	resume        bool
	logPath       string
	evidenceDir   string
	runID         string
	setOwner      bool
	jsonSummary   string
	runStart      time.Time
	s             *spec.Spec
	validate      bool
}

type logHandles struct {
	logFile *os.File
	logOut  io.Writer
}

type buildConfigResult struct {
	cfg             runpkg.Config
	params          tuning.Params
	tuningMatched   bool
	dryRunEffective bool
}

// preflightResult carries what postProcessFlags computed out of the flag set,
// for runWithFlagSet to consume before it moves on to spec load and transport
// validation.
type preflightResult struct {
	excludes       []string
	explicit       map[string]bool
	workersTyped   bool
	target         string
	authCred       *nfs41.AuthSys
	profileCleanup []func()
}

// registerFlags registers the whole flag surface on fs and reports it, together
// with the platform gate that refuses what this build cannot do.
func registerFlags(fs *flag.FlagSet, errOut io.Writer) (*flag.FlagSet, *flags) {
	fs.SetOutput(errOut)
	g := &cmdflags.Gate{OS: caps.OS, Arch: runtime.GOARCH}
	f := &flags{gate: g, excludes: &stringList{}, partitionOnly: &stringList{}}
	specPath := fs.String("spec", "", "YAML permission spec file (required)")
	workers := fs.Int("workers", defaultWorkersFallback, "parallel workers, maximum 8192"+userspaceDefaultNote())
	dryRun := fs.Bool("dry-run", false, "show what would change without applying")
	validate := fs.Bool("validate", false, "check permissions against spec without making changes; exit 1 if mismatches found")
	logPath := fs.String("log", "", "error log file path: errors only (walk, apply, dir-fix, validation mismatches)")
	auditLogPath := fs.String("audit-log", "", "deprecated: use --evidence-dir. Writes the evidence directory PATH as one uncompressed shard")
	evidenceDir := fs.String("evidence-dir", "", "write per-object evidence -- record shards and manifest.json -- to this new or empty directory (~100 bytes per object before compression)")
	evidenceProfile := fs.String("evidence-profile", string(evidence.ProfileCompact), "evidence detail: compact (outcome and path) or detailed (adds each object's state before the write; on nfsv4 one extra batched ACL read per object)")
	evidenceShardMB := fs.Int("evidence-shard-mb", evidence.DefaultShardBytes>>20, "start a new evidence shard after this many MiB of records")
	evidenceGzip := fs.Bool("evidence-gzip", true, "gzip evidence shards")
	usePfindFlag := g.Bool(fs, cmdflags.Pfind(caps), "pfind", false,
		"enumerate with pfind instead of the built-in parallel walk")
	noPfind := g.Bool(fs, cmdflags.Pfind(caps), "no-pfind", false,
		"deprecated: the parallel walk is now the default")
	compare := fs.Bool("compare", false, "read current ACL/mode before writing; skip if already correct")
	ckptPath := fs.String("checkpoint", "", "checkpoint file path (enables directory-level resume)")
	resume := fs.Bool("resume", false, "resume from existing checkpoint (requires --checkpoint)")
	quiet := fs.Bool("quiet", false, "suppress progress output")
	jsonSummary := fs.String("json-summary", "", "write a machine-readable JSON run summary to PATH")
	setOwner := fs.Bool("set-owner", false, "apply owner/group from spec (requires root or CAP_CHOWN)")
	batchSize := fs.Int("batch-size", 50, "paths per worker batch (maximum 65536)")
	applyFlag := fs.Bool("apply", false, "actually apply changes (without this, defaults to dry-run)")
	skipIdentityCheck := fs.Bool("skip-identity-check", false, "skip pre-resolution of named principals (use with numeric UIDs/GIDs)")
	fs.Var(f.excludes, "exclude", "glob pattern of paths to skip; repeatable, unioned with the spec's exclude list. A pattern without / matches a base name anywhere in the tree; with / it matches the path relative to TARGET. Matched directories are pruned")
	oneFilesystem := fs.Bool("one-filesystem", false, "do not cross filesystem boundaries (skip nested mounts)")
	showVersion := fs.Bool("version", false, "print version and exit")
	// --transport is registered normally, NOT through the gate: the flag is
	// supported everywhere and only the value "kernel" is not. Hiding it would
	// leave a Mac operator unable to discover that --transport=userspace, the
	// value the docs teach, is exactly what works for them.
	transportName := fs.String("transport", defaultTransport(),
		"filesystem transport: kernel (mounted export) or userspace (direct NFSv4.1)")
	g.Value("transport", "kernel", cmdflags.KernelTransport(caps))
	server := fs.String("server", "", userspaceOnly("NFS server HOST[:PORT]; port defaults to 2049"))
	export := fs.String("export", "", userspaceOnly("export path on the server"))
	connections := fs.Int("connections", 16, userspaceOnly("TCP connections, one session each"))
	slots := fs.Int("slots", 0, userspaceOnly("per-session slot cap; 0 uses the server's grant"))
	maxOpsPerCompound := fs.Int("max-ops-per-compound", 0, userspaceOnly("0 uses the server's ca_maxoperations"))
	rpcTimeout := fs.Duration("rpc-timeout", 30*time.Second, userspaceOnly("per-COMPOUND deadline"))
	retryBudget := fs.Int("retry-budget", 5, userspaceOnly("attempts before an object is failed"))
	retryBaseDelay := fs.Duration("retry-base-delay", 100*time.Millisecond, userspaceOnly("exponential backoff base"))
	authFlags := cmdflags.RegisterAuth(fs, userspaceOnly)
	sacl := cmdflags.RegisterSacl(fs)
	acceptFlatten := cmdflags.RegisterAcceptDACLFlattening(fs)
	allowHighIDs := cmdflags.RegisterAllowHighIDs(fs)
	unsafeAllowNonPure := fs.Bool("unsafe-allow-non-pure-server", false, "")
	supportBundle := fs.String("support-bundle", "", "collect a support bundle to PATH.tar.gz instead of running a repair; composes with --spec, --json-summary, --checkpoint and --log naming a previous run's artifacts")
	noRedact := fs.Bool("no-redact", false, "do not hash principal and owner/group names in the collected support bundle")
	// cpuprofile writes a pprof CPU profile for the whole run. Hidden from
	// --help by the empty usage string, same mechanism as the override above,
	// and for a similar reason: it is for whoever is debugging a transport, not
	// for operators. It exists because the phase 3 benchmark measured the
	// userspace transport burning roughly twelve times the kernel transport's
	// user CPU per object, and that question cannot be answered from counters.
	cpuProfile := fs.String("cpuprofile", "", "")
	// memprofile is hidden for the same reason as cpuprofile, but it does not
	// work the same way. A heap profile written only at exit is worthless for
	// the question it exists to answer: the run that motivated it was
	// OOM-killed, so there was no exit at all, and even a run that finishes has
	// already released its peak by the time it does. This writes a fresh
	// snapshot on an interval, overwriting in place, so the last snapshot before
	// the kill survives and names what was live.
	memProfile := fs.String("memprofile", "", "")
	memProfileInterval := fs.Duration("memprofile-interval", 30*time.Second, "")
	// rpc-stats prints the write-path report: achieved gather depth, arrival
	// rate, client CPU saturation, and whether a deliberate linger in the write
	// loop would pay. Hidden because it answers a transport-development
	// question, not an operator one. The counters it reads increment
	// unconditionally, so the flag only decides whether the numbers are printed.
	rpcStats := fs.Bool("rpc-stats", false, "")
	partitions := fs.String("partitions", "", "run the partition manifest at PATH instead of one TARGET: root, spec, excludes and state directory come from the manifest, and each partition gets its own checkpoint and evidence (docs/partitions.md)")
	fs.Var(f.partitionOnly, "partition", "with --partitions, run only the named partition; repeatable. The others keep their recorded status")
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: permissionreset [flags] TARGET")
		fs.VisitAll(func(f *flag.Flag) {
			if f.Usage == "" {
				return
			}
			fmt.Fprintf(errOut, "  -%s\n    \t%s", f.Name, f.Usage)
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				fmt.Fprintf(errOut, " (default %s)", f.DefValue)
			}
			fmt.Fprintln(errOut)
		})
	}

	f.specPath = specPath
	f.workers = workers
	f.dryRun = dryRun
	f.validate = validate
	f.logPath = logPath
	f.auditLogPath = auditLogPath
	f.evidenceDir = evidenceDir
	f.evidenceProfile = evidenceProfile
	f.evidenceShardMB = evidenceShardMB
	f.evidenceGzip = evidenceGzip
	f.usePfindFlag = usePfindFlag
	f.noPfind = noPfind
	f.compare = compare
	f.ckptPath = ckptPath
	f.resume = resume
	f.quiet = quiet
	f.jsonSummary = jsonSummary
	f.setOwner = setOwner
	f.batchSize = batchSize
	f.applyFlag = applyFlag
	f.skipIdentityCheck = skipIdentityCheck
	f.oneFilesystem = oneFilesystem
	f.showVersion = showVersion
	f.transportName = transportName
	f.server = server
	f.export = export
	f.connections = connections
	f.slots = slots
	f.maxOpsPerCompound = maxOpsPerCompound
	f.rpcTimeout = rpcTimeout
	f.retryBudget = retryBudget
	f.retryBaseDelay = retryBaseDelay
	f.unsafeAllowNonPure = unsafeAllowNonPure
	f.supportBundle = supportBundle
	f.noRedact = noRedact
	f.cpuProfile = cpuProfile
	f.memProfile = memProfile
	f.memProfileInterval = memProfileInterval
	f.rpcStats = rpcStats
	f.authFlags = authFlags
	f.sacl = sacl
	f.acceptFlatten = acceptFlatten
	f.allowHighIDs = allowHighIDs
	f.partitions = partitions
	return fs, f
}

// postProcessFlags runs everything runWithFlagSet needs to do immediately
// after fs.Parse succeeds: gate rejection, --version, --support-bundle, auth
// resolution and its preflight warning, CPU/memory profiling setup, and the
// positional-argument / --spec checks. It returns (nil, code) on every early
// exit (version printed, bundle written, validation failure) and
// (*preflightResult, 0) -- the 0 is ignored by the caller -- once the run
// should continue.
//
// CPU and memory profiling both install cleanup that must run when
// runWithFlagSet returns, not when this function returns, so instead of
// deferring here it collects those cleanups into profileCleanup for the
// caller to defer.
func postProcessFlags(fs *flag.FlagSet, f *flags, out, errOut io.Writer) (*preflightResult, int) {
	specPath, validate := f.specPath, f.validate
	transportName := f.transportName
	supportBundle, noRedact := f.supportBundle, f.noRedact
	jsonSummary, ckptPath, logPath := f.jsonSummary, f.ckptPath, f.logPath
	applyFlag := f.applyFlag
	cpuProfile, memProfile, memProfileInterval := f.cpuProfile, f.memProfile, f.memProfileInterval
	g := f.gate

	excludes := *f.excludes

	explicit := tuning.Explicit(fs)
	// Refused here, after parsing, so the message names the missing capability
	// rather than leaving the flag package to report an unknown flag.
	// tuning.Explicit lists TYPED flags, so a gated flag resting at its default
	// passes through silently; the value map is consulted regardless, because an
	// unsupported value that arrived as a default is just as broken as one typed.
	if g.Reject(explicit, map[string]string{"transport": *transportName}, errOut) {
		return nil, 1
	}
	workersTyped := explicit["workers"]

	if *f.showVersion {
		fmt.Fprintf(out, "permissionreset %s (%s) built %s\n", version, commit, date)
		return nil, 0
	}

	// The support-bundle mode returns before anything else in run() happens, and
	// that placement is the design: it must work in exactly the situations a
	// repair does not. No TARGET is required, --spec is optional and is read as
	// bytes rather than loaded (a spec that fails to parse is a common reason to
	// collect a bundle in the first place), no transport is constructed, and no
	// checkpoint is opened for writing. Collecting diagnostics must never be
	// gated on the thing being diagnosed still working.
	if *supportBundle != "" {
		if err := writeSupportBundle(bundleInputs{
			SpecPath:       *specPath,
			SummaryPath:    *jsonSummary,
			CheckpointPath: *ckptPath,
			LogPath:        *logPath,
			NoRedact:       *noRedact,
			Version:        version,
			Commit:         commit,
			Date:           date,
		}, *supportBundle); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return nil, 1
		}
		fmt.Printf("Support bundle written: %s\n", *supportBundle)
		fmt.Println("Review bundle/README.txt inside it before sending: filesystem paths are present.")
		return nil, 0
	}

	authCred, authWarnings, authErr := f.authFlags.Resolve(explicit, *transportName)
	if authErr != nil {
		fmt.Fprintf(errOut, "error: %v\n", authErr)
		return nil, 1
	}
	for _, w := range authWarnings {
		fmt.Fprintln(errOut, w)
	}
	// Preflight is the other half of the credential mitigation and it does NOT
	// run on a dry run (internal/run/run.go, under if !cfg.DryRun, and any run
	// without --apply is a dry run) -- nor on --validate, which returns from
	// run.Run at the cfg.Validate branch before ProbePreflight is reached, so it
	// skips preflight even under --apply. Say so on both, rather than letting a
	// clean-looking plan or a clean validate report read as a validated
	// credential.
	if *transportName == "userspace" && (!*applyFlag || *validate) {
		fmt.Fprintln(errOut, "note: the AUTH_SYS credential has not been exercised against the "+
			"export; the preflight ACL write happens only on a repair run under --apply")
	}

	var profileCleanup []func()

	if *cpuProfile != "" {
		cpuFile, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: create CPU profile %s: %v\n", *cpuProfile, err)
			return nil, 1
		}
		profileCleanup = append(profileCleanup, func() { cpuFile.Close() })
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			fmt.Fprintf(errOut, "ERROR: start CPU profile: %v\n", err)
			return nil, 1
		}
		// run() returns rather than calling os.Exit, so this defer runs. main()
		// is the only place os.Exit appears, and it is reached after run() has
		// returned.
		profileCleanup = append(profileCleanup, pprof.StopCPUProfile)
	}

	if *memProfile != "" {
		if *memProfileInterval <= 0 {
			fmt.Fprintf(errOut, "ERROR: --memprofile-interval must be positive, got %s\n", *memProfileInterval)
			return nil, 1
		}
		// One snapshot before the run so there is always a profile on disk, even
		// if the process dies inside the first interval.
		writeHeapProfile(*memProfile, errOut)
		stop := make(chan struct{})
		profileCleanup = append(profileCleanup, func() { close(stop) })
		go func() {
			t := time.NewTicker(*memProfileInterval)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					writeHeapProfile(*memProfile, errOut)
				}
			}
		}()
	}

	// A partitioned run takes its root and spec from the manifest;
	// runPartitioned refuses the flags that would contradict it.
	if *f.partitions != "" {
		return &preflightResult{
			excludes: excludes, explicit: explicit, workersTyped: workersTyped,
			authCred: authCred, profileCleanup: profileCleanup,
		}, 0
	}
	if len(*f.partitionOnly) > 0 {
		fmt.Fprintln(errOut, "ERROR: --partition requires --partitions")
		return nil, 1
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(errOut, "usage: permissionreset [flags] TARGET")
		return nil, 1
	}
	target := fs.Arg(0)

	if *specPath == "" {
		fmt.Fprintln(errOut, "ERROR: --spec is required")
		return nil, 1
	}

	// Exclude patterns are checked here, before the spec is loaded and before
	// setupLogging creates anything. os.Create truncates, so validating later
	// would empty an operator's existing --log file on a command line that is
	// about to be rejected anyway.
	for _, p := range excludes {
		if err := spec.ValidateExcludePattern(p); err != nil {
			fmt.Fprintf(errOut, "ERROR: --exclude: %v\n", err)
			return nil, 1
		}
	}

	return &preflightResult{
		excludes:       excludes,
		explicit:       explicit,
		workersTyped:   workersTyped,
		target:         target,
		authCred:       authCred,
		profileCleanup: profileCleanup,
	}, 0
}

func runWithFlagSet(args []string, out, errOut io.Writer) (exitCode int) {
	fs, f := registerFlags(flag.NewFlagSet("permissionreset", flag.ContinueOnError), errOut)
	specPath, validate := f.specPath, f.validate
	logPath := f.logPath
	usePfindFlag := f.usePfindFlag
	ckptPath, resume, jsonSummary := f.ckptPath, f.resume, f.jsonSummary
	setOwner, batchSize := f.setOwner, f.batchSize
	oneFilesystem := f.oneFilesystem
	transportName, server, export := f.transportName, f.server, f.export
	connections := f.connections

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	pf, code := postProcessFlags(fs, f, out, errOut)
	if pf == nil {
		return code
	}
	for _, fn := range pf.profileCleanup {
		defer fn()
	}
	if *f.partitions != "" {
		return runPartitioned(fs, f, pf, out, errOut)
	}
	excludes := pf.excludes
	explicit := pf.explicit
	workersTyped := pf.workersTyped
	target := pf.target
	authCred := pf.authCred

	// TARGET is canonicalized inside the transport switch, not here. What "canonical"
	// means is a property of the transport: on the kernel transport TARGET is a local
	// path and EvalSymlinks/Abs/Stat are the right questions to ask about it, while on
	// the userspace transport it is a *server-side* path that no local syscall can
	// answer for. Asking anyway is not merely useless, it is wrong twice over -- it
	// fails at lstat for every real server path, and where a same-named local tree
	// happens to exist it silently rewrites the path through local symlinks and the
	// local cwd, addressing a different server-side object than the one typed.

	s, err := spec.Load(*specPath)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	// The spec is digested here, at load time, rather than at summary-writing
	// time: the file can be edited while a multi-hour run is in flight, and the
	// digest is only evidence if it is of the bytes this run actually loaded.
	runStart := time.Now()
	specDigest, digestErr := summary.FileDigest(*specPath)
	if digestErr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not digest spec %s: %v\n", *specPath, digestErr)
	}

	// The client gate logs the observed server value before it can return an
	// intentionally opaque refusal. Keep that sink available during construction.
	evOpts, err := evidenceOptions(f, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	lh, err := setupLogging(*logPath)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	if lh.logFile != nil {
		// The error log is evidence too: a close that fails (NFS reports a
		// deferred write error here) fails the run rather than vanishing.
		defer func() {
			if err := lh.logFile.Close(); err != nil {
				fmt.Fprintf(errOut, "ERROR: close log %s: %v\n", *logPath, err)
				if exitCode == 0 {
					exitCode = 1
				}
			}
		}()
	}
	runID := newRunID()
	sink, err := openSink(evOpts, runID)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	// TARGET canonicalization and command-line rejection stay in the command.
	// internal/run receives only a configuration that has passed these gates.
	target, err = validateTransport(target, f, s, excludes, explicit, workersTyped, errOut)
	if err != nil {
		return 1
	}

	bcr, err := buildConfig(target, s, excludes, explicit, workersTyped, authCred, lh.logOut, sink, f, out, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	// Signal ownership remains a command concern. The package receives only the
	// cancellation context, so it can also be driven by another binary or a test.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keep the established signal message as well as using NotifyContext. The first
	// signal cancels the run; a second restores the default disposition and resends
	// itself so an operator always retains an immediate escape hatch.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	runDone := make(chan struct{})
	sigMessageDone := make(chan struct{})
	go func() {
		signals.Watch(sigCh, runDone, errOut, func(sig os.Signal) {
			signals.Escalate(sig, stop, sigCh)
		})
		close(sigMessageDone)
	}()

	res, err := runCommand(ctx, bcr.cfg, out)
	close(runDone)
	<-sigMessageDone
	if err != nil {
		if errors.Is(err, nfs41.ErrNotPureServer) || errors.Is(err, nfs41.ErrFlashArrayNotSupported) {
			fmt.Fprintln(errOut, transportError(err))
		}
		reportCheckpointUnflushed(os.Stderr, err, *ckptPath)
		reportTraverseNotPreserved(os.Stderr, err)
	}
	exitCode = exitCodeFor(err)

	_, exitCode = buildSummary(res, exitCode, buildSummaryOpts{
		target:        target,
		transportName: *transportName,
		server:        *server,
		export:        *export,
		specPath:      *specPath,
		specDigest:    specDigest,
		batchSize:     *batchSize,
		connections:   *connections,
		usePfind:      *usePfindFlag,
		oneFilesystem: *oneFilesystem,
		ckptPath:      *ckptPath,
		resume:        *resume,
		logPath:       *logPath,
		evidenceDir:   evidenceDirOf(evOpts),
		runID:         runID,
		setOwner:      *setOwner,
		jsonSummary:   *jsonSummary,
		runStart:      runStart,
		s:             s,
		validate:      *validate,
	})

	return exitCode
}

// validateTransport validates excludes, canonicalizes TARGET for the selected
// transport, and range-checks --workers and --batch-size. It prints its own
// diagnostics to errOut and returns a non-nil error on any failure; callers
// need only check err and return their own exit code.
func validateTransport(target string, f *flags, s *spec.Spec, excludes []string, explicit map[string]bool, workersTyped bool, errOut io.Writer) (string, error) {
	transportName, server, export := f.transportName, f.server, f.export
	usePfindFlag, noPfind := f.usePfindFlag, f.noPfind
	workers, batchSize := f.workers, f.batchSize

	var err error
	switch *transportName {
	case "kernel":
		if *server != "" || *export != "" {
			fmt.Fprintln(errOut, "ERROR: --server and --export require --transport=userspace")
			return "", errors.New("--server and --export require --transport=userspace")
		}
		target, err = targetForKernel(target)
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: %v\n", err)
			return "", err
		}
	case "userspace":
		if *usePfindFlag {
			fmt.Fprintln(errOut, "error: --pfind is not supported with --transport=userspace")
			fmt.Fprintln(errOut, "  pfind enumerates through a mounted path and cannot be fused with the fix")
			return "", errors.New("--pfind is not supported with --transport=userspace")
		}
		if s.Protocol == "smb" {
			fmt.Fprintln(errOut, "error: the smb backend is not supported with --transport=userspace")
			fmt.Fprintln(errOut, "  smbcacls operates on a UNC path and has no NFSv4.1 equivalent")
			return "", errors.New("the smb backend is not supported with --transport=userspace")
		}
		if *server == "" || *export == "" {
			fmt.Fprintln(errOut, "error: --transport=userspace requires --server and --export")
			fmt.Fprintln(errOut, "  userspace connects directly and cannot infer either value from a mounted path")
			return "", errors.New("--transport=userspace requires --server and --export")
		}
		target, err = targetForUserspace(target, *export)
		if err != nil {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return "", err
		}
	default:
		fmt.Fprintf(errOut, "error: unknown --transport %q (want kernel or userspace)\n", *transportName)
		return "", fmt.Errorf("unknown --transport %q", *transportName)
	}

	if *noPfind {
		fmt.Fprintln(errOut, "NOTE: --no-pfind is deprecated and now the default")
	}

	if workersTyped && *workers < 1 {
		fmt.Fprintf(errOut, "ERROR: --workers must be >= 1 (got %d)\n", *workers)
		return "", fmt.Errorf("--workers must be >= 1 (got %d)", *workers)
	}
	if workersTyped && *workers > maxTunedWorkers {
		fmt.Fprintf(errOut, "ERROR: --workers must be <= %d (got %d)\n", maxTunedWorkers, *workers)
		return "", fmt.Errorf("--workers must be <= %d (got %d)", maxTunedWorkers, *workers)
	}
	if explicit["batch-size"] && (*batchSize < 1 || *batchSize > maxTunedBatchSize) {
		fmt.Fprintf(errOut, "ERROR: --batch-size must be between 1 and %d (got %d)\n", maxTunedBatchSize, *batchSize)
		return "", fmt.Errorf("--batch-size must be between 1 and %d (got %d)", maxTunedBatchSize, *batchSize)
	}

	return target, nil
}

// newRunID returns a random 128-bit identifier for one run, so two summaries
// of the same target and spec can still be told apart.
func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// verificationFor states what this run's counts prove, in the summary's
// verification terms. A repair run checks nothing after writing, so its
// verdict is not_requested however clean its writes were; only --validate
// selects a required dimension. Enumeration is complete only when no walk or
// readdir error, interruption or duplicate completion left part of the tree
// unlisted or uncounted.
func verificationFor(res runpkg.Result) (summary.Accounting, summary.Verification) {
	st := res.Stats
	complete := res.WalkErrors == 0 && res.ReaddirErrors == 0 && !res.Interrupted && res.DuplicateCompletions == 0 &&
		!res.EvidenceStopped
	acc := summary.Accounting{
		Included: st.Enumerated, Excluded: st.Excluded,
		Unverified: st.Enumerated, EnumerationComplete: complete,
	}

	if res.IsValidate {
		c := summary.Coverage{
			Eligible: max(0, st.Enumerated-st.Symlinks), Matched: res.MatchCount,
			Mismatched: res.MismatchCount, Unreadable: res.UnreadableCount,
			EnumerationComplete: complete,
		}
		c.NotChecked = max(0, c.Eligible-c.Matched-c.Mismatched-c.Unreadable)
		c.Eligible = c.Matched + c.Mismatched + c.Unreadable + c.NotChecked
		acc.Unverified = max(0, st.Enumerated-c.Matched-c.Mismatched)
		return acc, summary.NewVerification(summary.NewDimension(summary.DimNFSSpecMatch, true, c))
	}

	if res.DryRun {
		return acc, summary.NewVerification()
	}
	acc.Attempted = st.Applied + st.Errors
	acc.Succeeded, acc.Failed = st.Applied, st.Errors
	acc.Included = max(acc.Included, acc.Attempted)
	acc.Unverified = acc.Included
	w := summary.NewDimension(summary.DimWriteAccepted, false, summary.Coverage{
		Eligible: acc.Attempted, Matched: st.Applied, Mismatched: st.Errors, EnumerationComplete: complete,
	})
	w.Note = "mismatched counts writes the server rejected"
	return acc, summary.NewVerification(w)
}

// buildSummary assembles the record of the run and renders it to the terminal
// and, if requested, to JSON. Both come from the same struct so the two
// cannot drift. Everything about the run itself comes from run.Result --
// internal/run is the only thing that knows the effective worker count,
// which filesystem answered, and the phase split -- and everything about how
// the run was asked for comes from opts.
func buildSummary(res runpkg.Result, exitCode int, opts buildSummaryOpts) (*summary.RunSummary, int) {
	sum := &summary.RunSummary{
		RunID:  opts.runID,
		Tool:   summary.Tool{Name: "permissionreset", Version: version, Commit: commit, Date: date},
		Target: opts.target,
		Transport: summary.Trans{
			Name:               opts.transportName,
			Server:             opts.server,
			Export:             opts.export,
			Platform:           res.Platform,
			FilesystemID:       res.FilesystemID,
			FilesystemIDSource: res.FilesystemIDSource,
		},
		Spec: summary.Spec{Path: opts.specPath, SHA256: opts.specDigest, Protocol: opts.s.Protocol},
		Options: summary.Opts{
			Workers:        res.Workers,
			BatchSize:      opts.batchSize,
			WorkersDefault: res.WorkersDefaulted,
			DryRun:         res.DryRun,
			Compare:        res.Compare,
			SetOwner:       opts.setOwner,
			Pfind:          opts.usePfind,
			OneFilesystem:  opts.oneFilesystem,
			Exclude:        res.Excludes,
			CheckpointPath: opts.ckptPath,
			Resume:         opts.resume,
			LogPath:        opts.logPath,
			EvidenceDir:    opts.evidenceDir,
		},
		Objects: summary.Counts{
			Enumerated: res.Stats.Enumerated,
			Applied:    res.Stats.Applied,
			Skipped:    res.Stats.Skipped,
			Symlinks:   res.Stats.Symlinks,
			Excluded:   res.Stats.Excluded,
			Failed:     res.Stats.Errors,
			Match:      res.MatchCount,
			Mismatch:   res.MismatchCount,
			AuditKept:  res.AuditKept,
		},
		Errors: summary.Errs{
			Walk:       res.WalkErrors,
			Apply:      res.Stats.Errors,
			DirFix:     int64(res.DirFixErrors),
			Duplicates: res.DuplicateCompletions,
			Total:      res.TotalErrors,
		},
		Prepass: summary.Pre{
			DirsFixed:      res.DirsFixed,
			Errors:         res.DirFixErrors,
			FixSeconds:     res.FixSeconds,
			ReaddirSeconds: res.ReaddirSeconds,
		},
		Phases: summary.Phase{
			PrepassSeconds: res.PrepassSeconds,
			ApplySeconds:   res.ApplySeconds,
			TotalSeconds:   res.Elapsed.Seconds(),
			Fused:          res.Fused,
		},
		Validate:    res.IsValidate,
		Interrupted: res.Interrupted,
		ExitCode:    exitCode,
	}
	if m := res.Evidence; m != nil {
		sum.Evidence = &summary.EvidenceStatus{
			Dir:            opts.evidenceDir,
			Manifest:       filepath.Join(opts.evidenceDir, evidence.ManifestName),
			Status:         m.Status,
			Reasons:        m.Reasons,
			Profile:        string(m.Profile),
			RecordsWritten: m.RecordsWritten,
			RecordsDropped: m.RecordsDropped,
			NotAttempted:   res.NotAttempted,
		}
		for _, sh := range m.Shards {
			sum.Records = append(sum.Records, summary.ShardRef{
				Path: filepath.Join(opts.evidenceDir, sh.Path), SHA256: sh.SHA256, Records: sh.Records,
			})
		}
	}
	// Only the userspace transport has a server and an export; leaving the empty
	// strings in would claim the kernel transport had a blank one.
	if opts.transportName != "userspace" {
		sum.Transport.Server = ""
		sum.Transport.Export = ""
	} else {
		sum.Options.Connections = opts.connections
	}
	sum.Accounting, sum.Verification = verificationFor(res)
	sum.Stamp(opts.runStart, time.Now())

	if res.FilesystemIDSource != "" {
		printRunDetail(sum)
	}

	if opts.jsonSummary != "" && res.FilesystemIDSource != "" {
		if err := sum.WriteFile(opts.jsonSummary); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: write JSON summary: %v\n", err)
			// A run that did its work must not be reported as failed because the
			// report could not be written -- but a harness that asked for the
			// file and did not get it has to hear about it, so this raises a
			// zero exit to one and leaves a non-zero one alone.
			if exitCode == 0 {
				exitCode = 1
			}
		} else {
			fmt.Printf("  Summary:    %s\n", opts.jsonSummary)
		}
	}

	return sum, exitCode
}

// buildConfig assembles the tuning parameters, prints the plan block, and
// builds the runpkg.Config that internal/run will execute. Signal handling
// stays a caller concern; this function only prepares what the run needs.
func buildConfig(target string, s *spec.Spec, excludes []string, explicit map[string]bool, workersTyped bool, authCred *nfs41.AuthSys, logOut io.Writer, sink *evidence.Sink, f *flags, out, errOut io.Writer) (*buildConfigResult, error) {
	baseParams := tuning.Params{
		Connections:       *f.connections,
		Slots:             *f.slots,
		Workers:           *f.workers,
		BatchSize:         *f.batchSize,
		MaxOpsPerCompound: *f.maxOpsPerCompound,
	}
	params, tuningMatched := applyTuningDefaults(explicit, target, *f.transportName, *f.server, *f.export, baseParams, errOut)
	if !workersTyped && !tuningMatched {
		params.Workers = 0
	}

	// The dry-run default is resolved inside internal/run, which prints its own
	// "DRY RUN (pass --apply to make changes)" line. The plan block still has to
	// say what the run will actually do, so the same rule is evaluated here --
	// read-only, without mutating the flag internal/run is about to interpret.
	dryRunEffective := *f.dryRun || !*f.applyFlag

	// The plan block goes here, after the spec has loaded and validated and after
	// the dry-run default has resolved, so what it prints about --apply is what
	// the run will actually do. It precedes the traverse check, the identity
	// pre-resolution and the preflight probe -- all of which now live in
	// internal/run, so printing before run.Run keeps that ordering: an operator
	// who reads the plan and sees the wrong target or the wrong rule set should be
	// able to abort before anything touches the tree.
	if !*f.validate {
		fmt.Println()
		spec.PrintPlan(os.Stdout, s, spec.PlanContext{
			Target:        target,
			Transport:     *f.transportName,
			OneFilesystem: *f.oneFilesystem,
			Apply:         !dryRunEffective,
			SetOwner:      *f.setOwner,
			Excludes:      spec.MergeExcludes(s.Exclude, excludes),
		})
	}

	cfg := runpkg.Config{
		Root:              target,
		SpecPath:          *f.specPath,
		Spec:              s,
		Transport:         *f.transportName,
		Server:            *f.server,
		Export:            *f.export,
		Workers:           params.Workers,
		BatchSize:         params.BatchSize,
		Connections:       params.Connections,
		Slots:             params.Slots,
		MaxOpsPerCompound: params.MaxOpsPerCompound,
		RPCTimeout:        *f.rpcTimeout,
		RetryBudget:       *f.retryBudget,
		RetryBaseDelay:    *f.retryBaseDelay,
		Apply:             *f.applyFlag,
		DryRun:            *f.dryRun,
		Compare:           *f.compare,
		Validate:          *f.validate,
		SetOwner:          *f.setOwner,
		OneFilesystem:     *f.oneFilesystem,
		Pfind:             *f.usePfindFlag,
		SkipIdentityCheck: *f.skipIdentityCheck,
		// From the SELECTED transport, never from the build platform: a Linux
		// --transport=userspace run talks to the same array a Mac does, and the
		// array is the authority for both.
		LocalIdentityAuthoritative: *f.transportName == "kernel",
		Quiet:                      *f.quiet,
		AllowNonPureServer:         *f.unsafeAllowNonPure,
		Auth:                       authCred,
		RPCStats:                   *f.rpcStats,
		Sacl:                       *f.sacl,
		AcceptDACLFlattening:       *f.acceptFlatten,
		AllowHighIDs:               *f.allowHighIDs,
		CheckpointPath:             *f.ckptPath,
		Resume:                     *f.resume,
		Exclude:                    excludes,
		Version:                    version,
		Log:                        logOut,
		Evidence:                   sink,
		ErrOut:                     errOut,
	}

	return &buildConfigResult{
		cfg:             cfg,
		params:          params,
		tuningMatched:   tuningMatched,
		dryRunEffective: dryRunEffective,
	}, nil
}

// printRunDetail renders the identifying facts about a run to stdout, below the
// counts. It is deliberately additive: every line the counts block printed
// before this existed still prints, unchanged and in the same order, because
// operators and scripts alike read that block.
func printRunDetail(sum *summary.RunSummary) {
	fmt.Printf("\nRun detail:\n")
	fmt.Printf("  Tool:       permissionreset %s (%s)\n", sum.Tool.Version, sum.Tool.Commit)
	fmt.Printf("  Target:     %s\n", sum.Target)
	fmt.Printf("  Transport:  %s (platform %s)\n", sum.Transport.Name, sum.Transport.Platform)
	if sum.Transport.Server != "" {
		fmt.Printf("  Server:     %s export %s\n", sum.Transport.Server, sum.Transport.Export)
	}
	if sum.Transport.FilesystemID != 0 {
		fmt.Printf("  Filesystem: %d (%s)\n", sum.Transport.FilesystemID, sum.Transport.FilesystemIDSource)
	} else {
		fmt.Printf("  Filesystem: unknown\n")
	}
	digest := sum.Spec.SHA256
	if digest == "" {
		digest = "unavailable"
	}
	fmt.Printf("  Spec:       %s\n", sum.Spec.Path)
	fmt.Printf("  Spec sha256: %s\n", digest)
	fmt.Printf("  Options:    workers=%d batch-size=%d", sum.Options.Workers, sum.Options.BatchSize)
	if sum.Options.Connections > 0 {
		fmt.Printf(" connections=%d", sum.Options.Connections)
	}
	fmt.Printf(" dry-run=%t compare=%t set-owner=%t one-filesystem=%t pfind=%t resume=%t\n",
		sum.Options.DryRun, sum.Options.Compare, sum.Options.SetOwner,
		sum.Options.OneFilesystem, sum.Options.Pfind, sum.Options.Resume)
	if len(sum.Options.Exclude) > 0 {
		fmt.Printf("  Exclude:    %s\n", strings.Join(sum.Options.Exclude, " "))
	}
	if sum.Options.CheckpointPath != "" {
		fmt.Printf("  Checkpoint: %s\n", sum.Options.CheckpointPath)
	}
	fmt.Printf("  Phases:     pre-pass %.1fs, apply %.1fs, total %.1fs (fused=%t)\n",
		sum.Phases.PrepassSeconds, sum.Phases.ApplySeconds, sum.Phases.TotalSeconds, sum.Phases.Fused)
	fmt.Printf("  Exit code:  %d\n", sum.ExitCode)
}

// reportTraverseNotPreserved gives the operator the remedy for a spec that would
// strip traverse from the running identity.
//
// internal/run prints the offending rule itself -- that is the condition, and
// reporting the condition is the library's job. What to do about it is the
// command's, by the same division reportCheckpointUnflushed follows: the
// diagnosis alone leaves an operator staring at a rejected spec with no
// indication that the fix is an execute bit on directory rules rather than a
// change to the target tree or the invoking account.
//
// This is an ordinary refusal and exits 1, not 3. Nothing was modified -- the
// check runs ahead of the identity pre-resolve and the preflight probe -- so
// there is no half-repaired tree and no untrustworthy checkpoint to warn about.
func reportTraverseNotPreserved(errOut io.Writer, err error) {
	if !errors.Is(err, runpkg.ErrTraverseNotPreserved) {
		return
	}
	fmt.Fprintln(errOut, "The spec's directory permissions would lock the walk out of child directories.")
	fmt.Fprintln(errOut, "Add execute/traverse permission for the running identity to directory rules.")
}

// reportCheckpointUnflushed gives the operator the advice the sentinel carries.
//
// internal/run prints the close failure itself, which tells a person what broke
// and nothing about what to do next. The instruction that matters -- do not
// --resume from this file -- lives in ErrCheckpointUnflushed's own text, and
// errors.Is is how automation reads that, not how a human does. Without this
// line the terminal shows a close error and an exit code nobody recognises, and
// the obvious next move is the one wrong move: re-run with --resume, which skips
// directories that were never finished and reports them as fixed. That is the
// exact durable wrong answer this whole split exists to prevent, so the guidance
// has to reach stderr.
//
// It lives in the command, not the library, for the same reason exitCodeFor
// does: internal/run's job is to report the condition, and talking to an
// operator -- including knowing which --checkpoint path they typed -- is the
// command's.
//
// The line is silent on every other error. Telling someone their checkpoint is
// untrustworthy when the repair merely failed would send them to re-repair a
// large tree from scratch for no reason, since a failed repair leaves a good
// checkpoint and --resume is the right thing to do with it.
func reportCheckpointUnflushed(errOut io.Writer, err error, checkpointPath string) {
	if !errors.Is(err, runpkg.ErrCheckpointUnflushed) {
		return
	}
	where := "the checkpoint"
	if checkpointPath != "" {
		where = checkpointPath
	}
	fmt.Fprintf(errOut, "ERROR: the repair itself succeeded, but %s was not flushed and no "+
		"longer describes this run — do NOT re-run with --resume from it; delete it and start "+
		"a fresh run if you need a checkpoint.\n", where)
}

// exitCodeFor is the whole exit-code vocabulary of this command, in one place.
//
//	0 — success
//	1 — the repair failed, --validate found mismatches, or a pre-flight check
//	    refused the spec before anything was modified (ErrTraverseNotPreserved)
//	2 — flag parsing failed (the flag package exits with this itself)
//	3 — the repair succeeded, but the checkpoint on disk is not trustworthy:
//	    do not --resume from it. Automation that would otherwise retry with
//	    --resume needs to tell this apart from 1, where the repair itself is
//	    what went wrong and the checkpoint is still good.
//
// internal/run guarantees the two cannot arrive together: it only substitutes
// ErrCheckpointUnflushed when the run had no error of its own, so 3 never masks
// a failed repair.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, runpkg.ErrCheckpointUnflushed):
		return 3
	default:
		return 1
	}
}

// stringList is a repeatable string flag. flag has no built-in slice type, and
// the alternative -- one comma-separated value -- cannot express a pattern
// containing a comma, which is a legal filename character.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, " ") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() { os.Exit(run()) }

func applyTuningDefaults(explicit map[string]bool, target, transportName, server, export string,
	base tuning.Params, errOut io.Writer,
) (tuning.Params, bool) {
	warn := func(format string, args ...any) {
		fmt.Fprintf(errOut, "WARNING: tuning: "+format+"; using built-in defaults\n", args...)
	}

	executable, err := executablePath()
	if err != nil {
		warn("find executable: %v", err)
		return base, false
	}
	path := tuning.PathForExecutable(executable)
	file, err := tuning.Load(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			warn("load %s: %v", path, err)
		}
		return base, false
	}

	host, err := hostname()
	if err != nil {
		warn("resolve client hostname: %v", err)
		return base, false
	}
	// permissionreset always looks up an exact solo-client key. A multi-client result
	// was measured under shared array load and must not tune one host in isolation.
	clients := []string{host}
	var key tuning.Key
	switch transportName {
	case "userspace":
		key, err = tuning.UserspaceKey(clients, server, export)
	case "kernel":
		mounts, openErr := openMounts()
		if openErr != nil {
			warn("open /proc/mounts: %v", openErr)
			return base, false
		}
		key, err = tuning.KernelKey(clients, target, mounts)
		if closeErr := mounts.Close(); closeErr != nil && err == nil {
			warn("close /proc/mounts: %v", closeErr)
			return base, false
		}
		if errors.Is(err, tuning.ErrNoMountForTarget) {
			return base, false
		}
	default:
		return base, false
	}
	if err != nil {
		warn("resolve %s key: %v", transportName, err)
		return base, false
	}

	entry, ok := file.Lookup(key)
	if !ok {
		return base, false
	}
	params, _ := tuning.Apply(base, entry.Params, explicit)
	if err := validateTuningParams(params, transportName, explicit); err != nil {
		warn("entry %s: %v", key.String(), err)
		return base, false
	}
	fmt.Fprintf(errOut, "tuning: %s from %s confidence=%s (%s)\n",
		key.String(), path, cmp.Or(entry.Measured.Confidence, "unknown"),
		announceParams(params, entry.Params, explicit))
	return params, true
}

// announceParams renders the effective values, marking each one a typed flag
// supplied with the value the file held instead.
//
// The line names the tuning file and then printed post-precedence values, so a
// flag that beat the file was reported as if the file had supplied it: typing
// --workers 256 against a file holding 1024 printed "from <file> ... workers=256".
// Showing only the file's values instead would misreport the run just as badly
// in the other direction, since those are not the values that execute. Marking
// the overridden ones is what makes both readable from one line.
func announceParams(effective, fromFile tuning.Params, typed map[string]bool) string {
	var b strings.Builder
	for i, f := range []struct {
		name             string
		value, fileValue int
	}{
		{"connections", effective.Connections, fromFile.Connections},
		{"slots", effective.Slots, fromFile.Slots},
		{"workers", effective.Workers, fromFile.Workers},
		{"batch-size", effective.BatchSize, fromFile.BatchSize},
		{"max-ops-per-compound", effective.MaxOpsPerCompound, fromFile.MaxOpsPerCompound},
	} {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", f.name, f.value)
		// Marked whenever the flag was typed, not only when the values differ:
		// the attribution is what the line gets wrong, and a typed flag that
		// happens to match the file still did not come from the file.
		if typed[f.name] {
			fmt.Fprintf(&b, "[flag, file %d]", f.fileValue)
		}
	}
	return b.String()
}

// validateTuningParams applies the shared persisted-entry contract against the
// live descriptor limit. A limit read failure skips only that live-host check;
// fixed schema and range validation still run.
func validateTuningParams(params tuning.Params, transportName string, explicit map[string]bool) error {
	var soft uint64 = ^uint64(0)
	var nofile unix.Rlimit
	if err := getRlimit(unix.RLIMIT_NOFILE, &nofile); err == nil {
		soft = nofile.Cur
	}
	return tuning.ValidateParams(params, transportName, explicit, soft)
}

// Kernel descriptor-starvation has been observed to enumerate only part of a
// remote tree, but the surviving measurement predates internal/run and cannot
// establish how the current code reports that outcome. Whether it now exits
// nonzero remains unmeasured. A live low-ulimit kernel run on the FSA lab NFS
// mount is the run that would settle it. Until then persisted values are refused
// up front when they cannot fit, and the sweeper independently rejects a trial
// whose applied count is materially below its prepared tree.

// targetForKernel canonicalizes TARGET as a local path: resolve symlinks, make it
// absolute, and require that it be a directory that exists. This is exactly what
// run() did unconditionally before the transport switch existed, moved to the one
// branch where a local syscall is the right way to answer the question.
//
// The returned errors carry no "ERROR: " prefix; the caller adds it, so the
// messages are byte-identical to the ones this command has always printed.
func targetForKernel(target string) (string, error) {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("resolve target: %w", err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("abs path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", abs)
	}
	// Reject dangerous targets.
	if abs == "/" {
		return "", errors.New("refusing to operate on filesystem root /")
	}
	return abs, nil
}

// targetForUserspace canonicalizes TARGET as a server-side path.
//
// Lexical only: filepath.Clean issues no syscall, so nothing here can be answered
// by -- or misled by -- the local filesystem. An absolute path is required rather
// than inferred, because the only thing filepath.Abs could prepend is the local
// working directory, which names nothing on the server.
//
// Containment is NOT enforced here. nfs41.normalizeConfig/pathWithinExport already
// compare the cleaned target against the cleaned export and reject anything outside
// it, and duplicating that comparison would create a second, drifting definition of
// what "inside the export" means. filepath.Clean and nfs41's path.Clean agree on
// every absolute slash-separated path, which is what makes handing the result
// straight to the client safe -- and is also what lets walk.Prepass recognise the
// root it is given as the transport's own root and pick up its filehandle.
//
// A target equal to the export root is the ordinary case and is allowed. The bare-/
// refusal survives only in the one shape where it still says something the export
// containment check does not: TARGET / under --export /, the whole-server case. With
// any other export, TARGET / is outside the export and the client refuses it.
func targetForUserspace(target, export string) (string, error) {
	if !strings.HasPrefix(target, "/") {
		return "", fmt.Errorf("TARGET must be an absolute server-side path with --transport=userspace: %q", target)
	}
	clean := filepath.Clean(target)
	if clean == "/" && filepath.Clean(export) == "/" {
		return "", errors.New("refusing to operate on the entire server root export (TARGET / with --export /)")
	}
	return clean, nil
}

// defaultWorkersFallback is the concurrency used wherever no measurement says
// otherwise, and in particular on the kernel transport, where it is the value
// this command has always used.
const defaultWorkersFallback = 128

// transportError renders a transport construction failure for the terminal.
//
// The FlashBlade gate refusal is rendered from ErrNotPureServer's own text and
// deliberately NOT from err. Two reasons, both load-bearing:
//
// The prefix. Every message in the userspace branch is lowercase "error: ", and the
// refusal is specified with that prefix verbatim; routing it through the generic
// "ERROR: %v" printed it as "ERROR: --transport=..." instead.
//
// The disclosure. Printing err would print whatever any future wrapper added to it.
// The gate's whole security property is that the *expected* max file size appears
// nowhere -- an error reading "expected 70368744177664" is a working instruction for
// defeating the gate -- so the text that reaches a terminal must come from the
// sentinel, which cannot grow a value, rather than from a chain that can.
func transportError(err error) string {
	if errors.Is(err, nfs41.ErrNotPureServer) {
		return "error: " + nfs41.ErrNotPureServer.Error()
	}
	// The FlashArray refusal is rendered from its own sentinel for the same two
	// reasons: the lowercase prefix, and keeping a wrapper from adding a value to
	// what reaches the terminal.
	if errors.Is(err, nfs41.ErrFlashArrayNotSupported) {
		return "error: " + nfs41.ErrFlashArrayNotSupported.Error()
	}
	return fmt.Sprintf("ERROR: %v", err)
}

// setupLogging opens --log.
func setupLogging(logPath string) (*logHandles, error) {
	lh := &logHandles{}
	if logPath != "" {
		logFile, err := os.Create(logPath)
		if err != nil {
			return nil, fmt.Errorf("create log: %v", err)
		}
		lh.logFile = logFile
		lh.logOut = logFile
	}
	return lh, nil
}

// evidenceOptions turns the evidence flags into sink options, or nil when no
// evidence was asked for. --audit-log is the deprecated spelling: it names the
// directory and keeps its old shape, one uncompressed file of records, so a
// script that reads it needs only to look inside the directory.
func evidenceOptions(f *flags, errOut io.Writer) (*evidence.Options, error) {
	dir := *f.evidenceDir
	if *f.auditLogPath != "" {
		if dir != "" {
			return nil, errors.New("--audit-log and --evidence-dir both name evidence; use --evidence-dir")
		}
		dir = *f.auditLogPath
		if fi, err := os.Stat(dir); err == nil && !fi.IsDir() {
			return nil, fmt.Errorf("--audit-log %s is a file; it now names an evidence directory (see --evidence-dir)", dir)
		}
		fmt.Fprintf(errOut, "WARNING: --audit-log is deprecated; it now writes the evidence directory %s "+
			"(records in %s/shard-000001.log, verdict in %s/%s). Use --evidence-dir.\n", dir, dir, dir, evidence.ManifestName)
		profile, err := evidence.ParseProfile(*f.evidenceProfile)
		if err != nil {
			return nil, err
		}
		return &evidence.Options{Dir: dir, Profile: profile, ShardBytes: -1}, nil
	}
	if dir == "" {
		return nil, nil
	}
	profile, err := evidence.ParseProfile(*f.evidenceProfile)
	if err != nil {
		return nil, err
	}
	if *f.evidenceShardMB < 1 {
		return nil, fmt.Errorf("--evidence-shard-mb must be >= 1 (got %d)", *f.evidenceShardMB)
	}
	return &evidence.Options{
		Dir: dir, Profile: profile,
		ShardBytes: int64(*f.evidenceShardMB) << 20, Compress: *f.evidenceGzip,
	}, nil
}

// openSink opens the evidence sink evOpts describes, or returns nil when
// evidence is off.
func openSink(evOpts *evidence.Options, runID string) (*evidence.Sink, error) {
	if evOpts == nil {
		return nil, nil
	}
	evOpts.RunID = runID
	return evidence.Open(*evOpts)
}

func evidenceDirOf(o *evidence.Options) string {
	if o == nil {
		return ""
	}
	return o.Dir
}
