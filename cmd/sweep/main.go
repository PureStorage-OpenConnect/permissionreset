// Command sweep measures transport tuneables against one host/target pair and
// writes the winner beside the permissionreset binary, which loads it as new
// defaults.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/signals"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
	"golang.org/x/sys/unix"
)

// version, commit and date are set with -ldflags -X, exactly as they are for
// cmd/permissionreset. commit is recorded in every entry this command writes: a
// measurement is only interpretable against the code that produced it, and
// shelling out to git would record the tree the sweep was launched from rather
// than the binary that did the measuring.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// assumedGenerateOpsPerSec converts --max-generate-time into a file ceiling when
// the operator gives no explicit --max-trial-files. It is a deliberately
// conservative stand-in for a number nothing has measured yet at that point:
// generation rate is not known until the probe tree is built, and the ceiling is
// needed before it. Roughly the low end of observed treegen stamping rates over
// NFS, so the derived ceiling errs toward a tree that finishes inside the stated
// budget rather than one that overruns it. --max-trial-files overrides it.
const assumedGenerateOpsPerSec = 2000

// driftHighConfidence is the largest opening-to-closing baseline drift a result
// may show and still be called high confidence. At or below it the array behaved
// the same at both ends of the sweep, so the ladders were compared against a
// stable target. Above it the winner may be an artifact of when it was measured,
// and the entry says so rather than being withheld: a low-confidence number an
// operator can see is worth more than a sweep that silently produced nothing.
const driftHighConfidence = 0.10

type commandDeps struct {
	// newProvisioner builds the generation backend. Injected so main_test.go can
	// exercise the mountless path without a mount; production passes a constructor
	// returning *posixProvisioner.
	newProvisioner func(localRoot, trialRoot string, base treegen.Config) ScratchProvisioner
	newRunner      func(run.Config, cacheController, io.Writer) TrialRunner
	load           func(string) (tuning.File, error)
	save           func(string, tuning.File) error
	now            func() time.Time
	hostname       func() (string, error)
	softNofile     func() (uint64, error)
	openMounts     func() (io.ReadCloser, error)
	openTrialLog   func(string, io.Writer) *trialLogWriter
}

func productionDeps() commandDeps {
	return commandDeps{
		newProvisioner: func(localRoot, _ string, base treegen.Config) ScratchProvisioner {
			return newPosixProvisioner(localRoot, base)
		},
		newRunner: newRunTrialRunner,
		load:      tuning.Load,
		save:      tuning.Save,
		now:       time.Now,
		hostname:  os.Hostname,
		softNofile: func() (uint64, error) {
			var limit unix.Rlimit
			if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
				return 0, err
			}
			return limit.Cur, nil
		},
		openMounts:   func() (io.ReadCloser, error) { return os.Open("/proc/mounts") },
		openTrialLog: openTrialLog,
	}
}

func main() { os.Exit(sweepMain()) }

type sweepProcess struct {
	notifyContext func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
	notify        func(chan<- os.Signal, ...os.Signal)
	stopSignal    func(chan<- os.Signal)
	escalate      func(os.Signal, func(), ...chan<- os.Signal)
	run           func(context.Context) int
	errOut        io.Writer
}

// sweepMain exists so os.Exit is reached only after every defer here has run.
func sweepMain() int {
	return runSweepProcess(sweepProcess{
		notifyContext: signal.NotifyContext,
		notify:        signal.Notify,
		stopSignal:    signal.Stop,
		escalate:      signals.Escalate,
		run: func(ctx context.Context) int {
			return execute(ctx, os.Args[1:], productionDeps(), os.Stdout, os.Stderr)
		},
		errOut: os.Stderr,
	})
}

func runSweepProcess(proc sweepProcess) int {
	// A signal cancels the context, which the search observes before its next
	// trial. Tree generation observes it too: treegen.RunContext checks ctx in its
	// seed build, fan-out and stamp phases, so a signal during generation stops it
	// rather than waiting for it to finish. What generation does not do is report
	// that uniformly -- the seed phase returns ctx.Err(), while the fan-out+stamp
	// phase stops its workers and returns success over a truncated tree -- so the
	// caller tests ctx.Err() itself instead of trusting generation's error alone.
	ctx, stop := proc.notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sigCh := make(chan os.Signal, 2)
	proc.notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer proc.stopSignal(sigCh)
	runDone := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		signals.Watch(sigCh, runDone, proc.errOut, func(sig os.Signal) {
			proc.escalate(sig, stop, sigCh)
		})
		close(watchDone)
	}()
	code := proc.run(ctx)
	close(runDone)
	<-watchDone
	return code
}

// sweepFlags holds every flag pointer registerSweepFlags produces, plus the
// gate that knows which of them this build refuses. It exists so the flag
// surface can be registered without running the command --
// TestEverySweepFlagIsClassified walks it.
type sweepFlags struct {
	gate *cmdflags.Gate

	scratch            *string
	scratchServerPath  *string
	transportName      *string
	server             *string
	export             *string
	specPath           *string
	principals         *string
	scaleName          *string
	copies             *int
	seedFiles          *int
	maxDepth           *int
	treeWorkers        *int
	seed               *int64
	safetyPrincipal    *string
	filesPerSubtree    *int
	trialDuration      *time.Duration
	maxGenerateTime    *time.Duration
	maxTrialFiles      *int64
	reuseScratch       *bool
	regenerateScratch  *bool
	force              *bool
	rpcTimeout         *time.Duration
	retryBudget        *int
	retryBaseDelay     *time.Duration
	trialLog           *string
	unsafeAllowNonPure *bool
	showVersion        *bool
	authFlags          *cmdflags.AuthFlags
}

// registerSweepFlags registers the whole flag surface on fs and reports it,
// together with the platform gate that refuses what this build cannot do.
func registerSweepFlags(fs *flag.FlagSet, errOut io.Writer) (*flag.FlagSet, *sweepFlags) {
	fs.SetOutput(errOut)
	g := &cmdflags.Gate{OS: caps.OS, Arch: runtime.GOARCH}
	f := &sweepFlags{gate: g, trialLog: new(string)}
	scratch := fs.String("scratch", "", "local mount path holding the trial tree (required whenever a consumer needs a local path)")
	scratchServerPath := fs.String("scratch-server-path", "", "server-side path of the trial tree under --export; skips /proc/mounts entirely")
	// --transport is registered normally, NOT through the gate: the flag is
	// supported everywhere and only the value "kernel" is not.
	transportName := fs.String("transport", defaultSweepTransport(), "transport to tune: kernel or userspace")
	g.Value("transport", "kernel", cmdflags.KernelTransport(caps))
	server := fs.String("server", "", "NFS server HOST[:PORT] (required for userspace)")
	export := fs.String("export", "", "export path on the server (required for userspace)")
	specPath := fs.String("spec", "", "YAML permission spec applied by every trial (required)")
	principals := fs.String("principals", "", "JSON roster mapping roles to NFS principals (required unless --reuse-scratch --force)")
	scaleName := fs.String("scale", "large", "tree size: small, medium, large, xlarge, huge")
	copies := fs.Int("copies", 0, "copy count; 0 lets calibration choose")
	seedFiles := fs.Int("seed-files", 0, "seed file count; 0 uses the scale value")
	maxDepth := fs.Int("max-depth", 0, "maximum tree depth; 0 uses the scale value")
	treeWorkers := fs.Int("tree-workers", 128, "concurrent workers for tree generation")
	seed := fs.Int64("seed", 42, "tree generation seed; a reused tree must record this same value")
	safetyPrincipal := fs.String("safety-principal", "", "override the safety ACE principal (default: the running user)")
	filesPerSubtree := fs.Int("files-per-subtree", 4, "explicit-ACE file outliers per project subtree")
	trialDuration := fs.Duration("trial-duration", 30*time.Second, "target work per trial; never below 10s")
	maxGenerateTime := fs.Duration("max-generate-time", 20*time.Minute, "generation budget used to derive a file ceiling")
	maxTrialFiles := fs.Int64("max-trial-files", 0, "hard ceiling on trial tree paths; 0 derives one from --max-generate-time")
	reuseScratch := fs.Bool("reuse-scratch", true, "measure an existing tree instead of generating one")
	regenerateScratch := fs.Bool("regenerate-scratch", false, "rebuild the trial tree even if one exists")
	force := fs.Bool("force", false, "sweep a tree permissionreset cannot prove it generated")
	rpcTimeout := fs.Duration("rpc-timeout", 30*time.Second, "per-COMPOUND deadline (userspace only)")
	retryBudget := fs.Int("retry-budget", 5, "attempts before an object is failed (userspace only)")
	retryBaseDelay := fs.Duration("retry-base-delay", 100*time.Millisecond, "exponential backoff base (userspace only)")
	fs.Func("trial-log", "JSON Lines trial log path; an explicit empty value disables recording", func(value string) error {
		*f.trialLog = value
		return nil
	})
	authFlags := cmdflags.RegisterAuth(fs, func(s string) string { return s + " (--transport=userspace only)" })
	unsafeAllowNonPure := fs.Bool("unsafe-allow-non-pure-server", false, "")
	showVersion := fs.Bool("version", false, "print version and exit")
	// --pfind is deliberately absent, not rejected: an external enumerator cannot
	// be fused with the fix, so a swept pfind number describes a path no repair
	// takes. Leaving the flag undefined makes the flag package refuse it.
	fs.Usage = func() {
		fmt.Fprintln(errOut, "usage: sweep [flags]")
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

	f.scratch = scratch
	f.scratchServerPath = scratchServerPath
	f.transportName = transportName
	f.server = server
	f.export = export
	f.specPath = specPath
	f.principals = principals
	f.scaleName = scaleName
	f.copies = copies
	f.seedFiles = seedFiles
	f.maxDepth = maxDepth
	f.treeWorkers = treeWorkers
	f.seed = seed
	f.safetyPrincipal = safetyPrincipal
	f.filesPerSubtree = filesPerSubtree
	f.trialDuration = trialDuration
	f.maxGenerateTime = maxGenerateTime
	f.maxTrialFiles = maxTrialFiles
	f.reuseScratch = reuseScratch
	f.regenerateScratch = regenerateScratch
	f.force = force
	f.rpcTimeout = rpcTimeout
	f.retryBudget = retryBudget
	f.retryBaseDelay = retryBaseDelay
	f.unsafeAllowNonPure = unsafeAllowNonPure
	f.showVersion = showVersion
	f.authFlags = authFlags
	return fs, f
}

func execute(ctx context.Context, args []string, deps commandDeps, out, errOut io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(errOut, "error: "+format+"\n", a...)
		return 1
	}

	fs, f := registerSweepFlags(flag.NewFlagSet("sweep", flag.ContinueOnError), errOut)
	g := f.gate
	scratch, scratchServerPath := f.scratch, f.scratchServerPath
	transportName, server, export := f.transportName, f.server, f.export
	specPath, principals, scaleName := f.specPath, f.principals, f.scaleName
	copies, seedFiles, maxDepth := f.copies, f.seedFiles, f.maxDepth
	treeWorkers, seed, safetyPrincipal := f.treeWorkers, f.seed, f.safetyPrincipal
	filesPerSubtree, trialDuration := f.filesPerSubtree, f.trialDuration
	maxGenerateTime, maxTrialFiles := f.maxGenerateTime, f.maxTrialFiles
	reuseScratch, regenerateScratch, force := f.reuseScratch, f.regenerateScratch, f.force
	rpcTimeout, retryBudget, retryBaseDelay := f.rpcTimeout, f.retryBudget, f.retryBaseDelay
	unsafeAllowNonPure, showVersion := f.unsafeAllowNonPure, f.showVersion

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	trialLogPath := *f.trialLog
	if *showVersion {
		fmt.Fprintf(out, "sweep %s (%s) built %s\n", version, commit, date)
		return 0
	}
	if fs.NArg() > 0 {
		return fail("unexpected argument %q; the trial tree is named by --scratch or --scratch-server-path", fs.Arg(0))
	}
	explicit := tuning.Explicit(fs)
	// Refused here, after parsing, so the message names the missing capability
	// rather than leaving the flag package to report an unknown flag. The value
	// map is consulted whether or not the flag was typed: an unsupported value
	// that arrived as a default is just as broken as one typed.
	if g.Reject(explicit, map[string]string{"transport": *transportName}, errOut) {
		return 1
	}

	authCred, authWarnings, authErr := f.authFlags.Resolve(explicit, *transportName)
	if authErr != nil {
		fmt.Fprintf(errOut, "error: %v\n", authErr)
		return 1
	}
	for _, w := range authWarnings {
		fmt.Fprintln(errOut, w)
	}

	if *transportName != "kernel" && *transportName != "userspace" {
		return fail("unknown --transport %q (want kernel or userspace)", *transportName)
	}
	if *transportName == "userspace" && (*server == "" || *export == "") {
		return fail("--transport=userspace requires --server and --export; userspace connects directly and cannot infer either from a mounted path")
	}
	if *specPath == "" {
		return fail("--spec is required: every trial applies it, and a sweep of a different spec measures different work")
	}
	if explicit["reuse-scratch"] && *reuseScratch && *regenerateScratch {
		return fail("--reuse-scratch and --regenerate-scratch ask for opposite things; give one")
	}
	if !*reuseScratch && !*regenerateScratch {
		return fail("--reuse-scratch=false requires --regenerate-scratch; name destructive replacement explicitly")
	}
	if *force && *regenerateScratch {
		return fail("--force and --regenerate-scratch ask for opposite things: --force adopts a tree read-only, while --regenerate-scratch replaces one; give one")
	}
	reuse := *reuseScratch && !*regenerateScratch
	if *principals == "" && !(reuse && *force) {
		return fail("--principals is required unless --force adopts an existing tree")
	}
	if *trialDuration < minTrialDuration {
		return fail("--trial-duration %s is below the %s minimum; below it session setup and the first round trips drown the knob effect", *trialDuration, minTrialDuration)
	}
	if *treeWorkers <= 0 {
		return fail("--tree-workers must be positive")
	}
	if *filesPerSubtree <= 0 {
		return fail("--files-per-subtree must be positive")
	}
	if *copies < 0 || *seedFiles < 0 || *maxDepth < 0 || *maxTrialFiles < 0 {
		return fail("--copies, --seed-files, --max-depth and --max-trial-files cannot be negative")
	}
	if *maxGenerateTime <= 0 {
		return fail("--max-generate-time must be positive")
	}
	if *retryBudget < 1 {
		return fail("--retry-budget must be at least 1")
	}
	// Zero means "use the default" to the transport, not "no limit":
	// internal/nfs41.normalizeConfig replaces a zero RPCTimeout with its 30s
	// default and a zero RetryBaseDelay with its own. An operator who types 0 at the
	// sweeper almost certainly means "no timeout", so every trial would be measured
	// under a setting they did not ask for and the entry would record it as theirs.
	// The sweeper refuses the ambiguity instead of silently resolving it.
	//
	// Negatives are deliberately not checked here: nfs41 already rejects them, with
	// a message that names the offending value.
	if *rpcTimeout == 0 {
		return fail("--rpc-timeout 0 means the transport's own 30s default, not an unlimited timeout; give an explicit duration")
	}
	if *retryBaseDelay == 0 {
		return fail("--retry-base-delay 0 means the transport's own default, not an immediate retry; give an explicit duration")
	}

	s, err := spec.Load(*specPath)
	if err != nil {
		return fail("%v", err)
	}
	var roster treegen.Roster
	if *principals != "" {
		roster, err = loadRoster(*principals)
		if err != nil {
			return fail("%v", err)
		}
	}

	scale, ok := treegen.Scales[*scaleName]
	if !ok {
		return fail("unknown --scale %q", *scaleName)
	}
	if *seedFiles > 0 {
		scale.SeedFiles = *seedFiles
	}
	if *maxDepth > 0 {
		scale.MaxDepth = *maxDepth
	}

	fileCeiling := *maxTrialFiles
	if fileCeiling == 0 {
		fileCeiling = int64(maxGenerateTime.Seconds() * assumedGenerateOpsPerSec)
		if fileCeiling < 1 {
			return fail("--max-generate-time %s leaves room for no files at all; give --max-trial-files", *maxGenerateTime)
		}
	}

	host, err := deps.hostname()
	if err != nil {
		return fail("resolve client hostname: %v", err)
	}
	softNofile, err := deps.softNofile()
	if err != nil {
		return fail("read soft RLIMIT_NOFILE: %v", err)
	}
	plan, err := newSearchPlan(*transportName, softNofile)
	if err != nil {
		return fail("%v", err)
	}
	outputPath, err := tuning.DefaultPath()
	if err != nil {
		return fail("%v", err)
	}

	// The generation backend is built before any root is resolved, because its own
	// answer -- not the transport name -- is half of what decides whether a local
	// path is needed at all.
	base := treegen.Config{
		Roster:          roster,
		Scale:           scale,
		Workers:         *treeWorkers,
		Seed:            *seed,
		SafetyPrincipal: *safetyPrincipal,
		FilesPerSubtree: *filesPerSubtree,
	}
	localScratch := *scratch
	if localScratch != "" {
		localScratch = filepath.Clean(localScratch)
	}
	prov := deps.newProvisioner(localScratch, *scratchServerPath, base)

	// Every scratch backend sweep can build today reads and writes the trial
	// tree through a mounted path. Where this build cannot mount a 4.1 export,
	// no invocation works -- not --reuse-scratch, not --force -- so say that
	// once, here, instead of failing later in resolveRoots on a missing
	// /proc/mounts, which names a Linux kernel path and explains nothing.
	//
	// Keyed on the provisioner, not on GOOS: a userspace provisioner returns
	// false and this refusal disappears with no edit.
	if prov.NeedsLocalMount() && !caps.KernelTransport {
		fmt.Fprintf(errOut,
			"error: sweep needs a kernel NFSv4.1 mount to read its trial tree, and this "+
				"build (%s/%s) cannot mount one. Every scratch backend sweep can use today "+
				"goes through a mounted path, so --reuse-scratch and --force do not help. "+
				"Run sweep on a Linux host with the export mounted.\n",
			caps.OS, runtime.GOARCH)
		return 1
	}

	// The one place the local-path requirement is decided. Nothing below re-derives
	// it from the transport or from the backend.
	needLocal := prov.NeedsLocalMount() || *transportName == "kernel" || *force

	roots, err := resolveRoots(deps, rootRequest{
		scratch:    *scratch,
		serverPath: *scratchServerPath,
		server:     *server,
		export:     *export,
		transport:  *transportName,
		force:      *force,
		needLocal:  needLocal,
		needsMount: prov.NeedsLocalMount(),
	})
	if err != nil {
		return fail("%v", err)
	}

	// The key names the transport's own target, not the local path: kernel takes it
	// from the resolved mount, userspace from the flags that define its target.
	keyServer, keyExport := *server, *export
	if *transportName == "kernel" {
		keyServer, keyExport = roots.mount.Server, roots.mount.Export
	}
	// permissionreset looks up an exact solo-client key built from os.Hostname, so the
	// sweep must write exactly that shape or its own result is unfindable.
	key, err := tuning.NewKey([]string{host}, keyServer, keyExport, *transportName)
	if err != nil {
		return fail("build tuning key: %v", err)
	}

	// Capture the run identity once so the default filename identifies this
	// invocation rather than whichever later phase happened to ask for the clock.
	sweepStarted := deps.now().UTC()
	if !explicit["trial-log"] {
		trialLogPath = deriveTrialLogPath(outputPath, key, sweepStarted)
	}
	var trialLog *trialLogWriter
	if trialLogPath != "" {
		fmt.Fprintf(out, "trial log: %s\n", trialLogPath)
		trialLog = deps.openTrialLog(trialLogPath, errOut)
		defer trialLog.close()
	}

	cache := newCacheController(*transportName, roots.mount.MountPoint, errOut)

	// The trial target is the tree addressed the way this transport addresses it:
	// a local path under the mount for kernel, a server-side path for userspace.
	trialTarget := roots.trialRoot
	if *transportName == "kernel" {
		trialTarget = roots.localRoot
	}
	baseConfig := run.Config{
		Root:               trialTarget,
		SpecPath:           *specPath,
		Spec:               s,
		Transport:          *transportName,
		RPCTimeout:         *rpcTimeout,
		RetryBudget:        *retryBudget,
		RetryBaseDelay:     *retryBaseDelay,
		AllowNonPureServer: *unsafeAllowNonPure,
		// Same rule as cmd/permissionreset: the selected transport decides, so a
		// kernel sweep keeps the fatal check it has today and a userspace sweep
		// -- on any platform -- treats a local miss as advisory.
		LocalIdentityAuthoritative: *transportName == "kernel",
		Quiet:                      true,
		ErrOut:                     errOut,
		// SACL mode (Sacl) stays off and is not offered as a flag: sweep trials
		// run on scratch trees it generates itself, which carry no audit ACEs.
		//
		// AllowHighIDs is on because sweep specs (examples/nfsv4_complex.yaml)
		// name FlashBlade's own 1000000000 + RID ids for domain SIDs with no
		// RFC 2307 id, which round-trip (RISKS.md #12). The scratch tree is
		// generated by the sweep itself, so no customer ACL is at stake.
		AllowHighIDs: true,
	}
	if *transportName == "userspace" {
		baseConfig.Server = *server
		baseConfig.Export = *export
		baseConfig.Auth = authCred
	}

	// Two runners over one configuration. The stock-baseline runner owns
	// calibration and both drift baselines; the search runner owns every candidate
	// and every confirmation. Keeping them apart makes each runner's last client
	// sample belong to a known kind of trial, so the winner sample cannot be
	// confused with a baseline one no matter when it is read. (The ordering here
	// already reads the sample before the closing baseline runs; the split is what
	// keeps that from being the only thing protecting it.)
	baselineRunner := deps.newRunner(baseConfig, cache, out)
	searchRunner := deps.newRunner(baseConfig, cache, out)
	if trialLog != nil {
		baselineRunner = &loggingRunner{inner: baselineRunner, log: trialLog}
		searchRunner = &loggingRunner{inner: searchRunner, log: trialLog}
	}

	stockTrial := func(ctx context.Context, _ string) (float64, error) {
		// The root argument is ignored deliberately. prepareScratch calibrates
		// against exactly its trial root, and baseConfig.Root already names that
		// same tree in this transport's own addressing.
		//
		// The calibration callback receives no manifest. Re-reading through the
		// provisioner is the only way to record the probe's path count without changing
		// scratch sizing's contract; failure is best-effort metadata and must not turn a
		// valid calibration into a failed sweep.
		files := int64(0)
		if manifest, found, inspectErr := prov.Inspect(ctx); inspectErr == nil && found {
			files = manifest.TotalPaths
		}
		return trialWithMetadata(ctx, baselineRunner, plan.baseline, trialMetadata{phase: "calibration", files: files})
	}

	scratchCfg := scratchConfig{
		LocalRoot:       roots.localRoot,
		TrialRoot:       roots.trialRoot,
		Roster:          roster,
		ScaleName:       *scaleName,
		Scale:           scale,
		CopiesOverride:  *copies,
		Workers:         *treeWorkers,
		Seed:            *seed,
		SafetyPrincipal: *safetyPrincipal,
		FilesPerSubtree: *filesPerSubtree,
		TrialDuration:   *trialDuration,
		MaxTrialFiles:   fileCeiling,
		Reuse:           reuse,
		Force:           *force,
	}
	prepared, err := prepareScratch(ctx, scratchCfg, prov, stockTrial, out)
	// Preparation is the longest phase of a sweep -- a large regenerate spends
	// twenty minutes here -- so it is where an operator is likeliest to reach for
	// Ctrl-C, and an interrupt here must end the same way an interrupt during the
	// search does: nothing measured, tuning file untouched, exit 130. Reporting it
	// as an ordinary failure would say the array or the flags were at fault.
	//
	// Both arms test ctx, and the deadline arm comes first. A deadline is a
	// failure, and an expired deadline also makes the interrupt arm's condition
	// true, so ordering is the only thing keeping a timeout from being reported as
	// the operator's own Ctrl-C.
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		detail := err
		if detail == nil {
			detail = ctx.Err()
		}
		return fail("preparing the trial tree ran out of time: %v", detail)
	case ctx.Err() != nil:
		// ctx, not err, is the test. Cancellation reaches this call in two shapes:
		// the seed phase returns ctx.Err() wrapped, while the fan-out+stamp phase
		// stops its workers and returns success over a truncated tree that its own
		// manifest records as whole. Only the signal itself sees both.
		fmt.Fprintf(errOut, "interrupted while preparing the trial tree: nothing was measured, so %s is unchanged\n", outputPath)
		// Only a generating run may be told to replace the tree. prepareScratch sends
		// every reuse and every --force invocation to reuseScratch, which creates
		// nothing -- and a --force reuse is exactly the shape that legally carries no
		// --principals, so the tree it adopted may be a colleague's, unrecreatable by
		// this tool, and was just declared foreign. Telling that operator to replace the
		// directory would destroy data on the tool's own instruction.
		if !reuse && !*force {
			fmt.Fprintf(errOut, "the tree at %s may be partial, and its %s can record that partial state as if it were complete; run --regenerate-scratch before sweeping it again\n",
				roots.trialRoot, treegen.ManifestName)
		}
		return 130
	case err != nil:
		return fail("%v", err)
	}
	setExpectedPaths(baselineRunner, prepared.TrialFiles)
	setExpectedPaths(searchRunner, prepared.TrialFiles)
	setTrialLogFiles(baselineRunner, prepared.TrialFiles)
	setTrialLogFiles(searchRunner, prepared.TrialFiles)

	// The opening baseline is measured over the whole prepared tree, and it is what
	// both the closing drift comparison and the duration floor are computed from.
	fmt.Fprintf(out, "Measuring the stock baseline over %s\n", prepared.TrialRoot)
	opening, err := trialWithMetadata(ctx, baselineRunner, plan.baseline, trialMetadata{phase: "opening_baseline"})
	if err != nil {
		return fail("opening baseline trial: %v", err)
	}
	if opening <= 0 || math.IsNaN(opening) || math.IsInf(opening, 0) {
		return fail("opening baseline measured %v paths/s", opening)
	}
	fmt.Fprintf(out, "  baseline %.0f paths/s over %d paths\n", opening, prepared.TrialFiles)

	// Reused, forced and explicit-copy trees still fail the floor unchanged. Only
	// automatic sizing owns both the shape measurement and permission to rebuild.
	required := int64(math.Ceil(opening * minTrialDuration.Seconds()))
	if prepared.TrialFiles < required && prepared.AutoSized {
		var grew bool
		prepared, grew, err = growScratch(ctx, scratchCfg, prov, prepared, opening, out)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			detail := err
			if detail == nil {
				detail = ctx.Err()
			}
			return fail("growing the trial tree ran out of time: %v", detail)
		}
		if ctx.Err() != nil {
			fmt.Fprintf(errOut, "interrupted while growing the trial tree: nothing was measured, so %s is unchanged\n", outputPath)
			fmt.Fprintf(errOut, "the tree at %s may be partial or markerless; run --regenerate-scratch before sweeping it again\n", roots.trialRoot)
			return 130
		}
		if err != nil {
			return fail("%v", err)
		}
		if grew {
			setExpectedPaths(baselineRunner, prepared.TrialFiles)
			setExpectedPaths(searchRunner, prepared.TrialFiles)
			setTrialLogFiles(baselineRunner, prepared.TrialFiles)
			setTrialLogFiles(searchRunner, prepared.TrialFiles)
			fmt.Fprintf(out, "Measuring a fresh stock baseline over the rebuilt tree at %s\n", prepared.TrialRoot)
			opening, err = trialWithMetadata(ctx, baselineRunner, plan.baseline, trialMetadata{phase: "opening_baseline"})
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				detail := err
				if detail == nil {
					detail = ctx.Err()
				}
				return fail("opening baseline over the rebuilt tree ran out of time: %v", detail)
			}
			if ctx.Err() != nil {
				fmt.Fprintf(errOut, "interrupted while measuring the rebuilt trial tree: nothing was measured, so %s is unchanged\n", outputPath)
				fmt.Fprintf(errOut, "the rebuilt tree at %s may be partial; run --regenerate-scratch before sweeping it again\n", roots.trialRoot)
				return 130
			}
			if err != nil {
				return fail("opening baseline trial after growth: %v", err)
			}
			if opening <= 0 || math.IsNaN(opening) || math.IsInf(opening, 0) {
				return fail("opening baseline after growth measured %v paths/s", opening)
			}
			fmt.Fprintf(out, "  baseline %.0f paths/s over %d paths\n", opening, prepared.TrialFiles)
			required = int64(math.Ceil(opening * minTrialDuration.Seconds()))
		}
		// When the ceiling prevented growth, the unchanged tree reaches the
		// ordinary floor refusal below. A second baseline would turn normal
		// variance into a pass/fail lottery.
	}
	if prepared.TrialFiles < required {
		return fail("the tree at %s measured %d files, which at %.0f paths/s is a %s trial; a trial requires %d files to reach the %s minimum",
			prepared.TrialRoot, prepared.TrialFiles, opening,
			roundSeconds(time.Duration(float64(prepared.TrialFiles)/opening*float64(time.Second))),
			required, minTrialDuration)
	}

	// Points are printed as they are measured, not after the search returns: a
	// full sweep is hours long, and an interrupted one must still show its work.
	result, searchErr := runSearchPlan(ctx, plan, searchRunner, func(p Point) {
		reportPoint(out, p)
	})

	measured := tuning.Measured{
		BaselineOpsPerSec: opening,
		TrialFiles:        prepared.TrialFiles,
		SweptAt:           deps.now().UTC(),
		SweepCommit:       commit,
	}
	if sample, ok := clientSample(searchRunner, host); ok {
		measured.PerClient = []tuning.ClientMeasurement{sample}
		measured.ClientBound = sample.Bound
	}

	if searchErr != nil {
		if !errors.Is(searchErr, ErrInterrupted) {
			// Ordinary failure: the operator's tuning file is left exactly as it was.
			return fail("%v", searchErr)
		}
		// Interrupted before any trial produced a rate. result.Best is still the
		// stock baseline that nothing measured, and writing it would hand the
		// repair binary a tuning the sweeper never observed. Losing an
		// interrupted sweep is the acceptable direction; inventing one is not.
		if !anyMeasured(result.Points) {
			fmt.Fprintf(errOut, "interrupted before any trial completed: nothing was measured, so %s is unchanged\n", outputPath)
			return 130
		}
		// Interrupted with data. The best point so far is real and is worth keeping,
		// but no confirmation ran, so no winner rate is invented for it.
		fmt.Fprintf(errOut, "interrupted: saving the best result so far with confidence partial\n")
		measured.Confidence = "partial"
		entry := entryFor(key, result.Best, measured)
		if err := persist(deps, outputPath, entry, softNofile, out); err != nil {
			return fail("%v", err)
		}
		return 130
	}

	closing, err := trialWithMetadata(ctx, baselineRunner, plan.baseline, trialMetadata{phase: "closing_baseline"})
	if err != nil {
		return fail("closing baseline trial: %v", err)
	}
	if closing <= 0 || math.IsNaN(closing) || math.IsInf(closing, 0) {
		return fail("closing baseline measured %v paths/s", closing)
	}

	drift := math.Abs(closing-opening) / opening
	measured.OpsPerSec = result.ConfirmedOpsPerSec
	measured.Confidence = "high"
	if drift > driftHighConfidence {
		measured.Confidence = "low"
	}
	fmt.Fprintf(out, "baseline drift %.1f%% (opening %.0f, closing %.0f): confidence %s\n",
		drift*100, opening, closing, measured.Confidence)
	// Printed from the same entry that is validated and persisted, so this line is
	// a usable cross-check that the saved entry belongs to the run just watched.
	entry := entryFor(key, result.Best, measured)
	winner := entry.Params
	fmt.Fprintf(out, "winner: connections=%d slots=%d workers=%d batch-size=%d max-ops-per-compound=%d at %.0f paths/s\n",
		winner.Connections, winner.Slots, winner.Workers, winner.BatchSize, winner.MaxOpsPerCompound, result.ConfirmedOpsPerSec)

	if err := persist(deps, outputPath, entry, softNofile, out); err != nil {
		return fail("%v", err)
	}
	if trialLog != nil {
		trialLog.write(trialLogSummary{
			Type:        "summary",
			Key:         key.String(),
			Clients:     append([]string(nil), key.Clients...),
			Server:      key.Server,
			Export:      key.Export,
			Transport:   key.Transport,
			SweepCommit: commit,
			TreeShape: trialLogTreeShape{
				Scale: *scaleName, Copies: prepared.Copies, SeedFiles: scale.SeedFiles,
				MaxDepth: scale.MaxDepth, Seed: *seed, FilesPerSubtree: *filesPerSubtree,
			},
			TrialFiles:               prepared.TrialFiles,
			Winner:                   logParams(entry.Params),
			ConfirmedMedianOpsPerSec: result.ConfirmedOpsPerSec,
			OpeningBaselineOpsPerSec: opening,
			ClosingBaselineOpsPerSec: closing,
			BaselineDrift:            drift,
			Confidence:               measured.Confidence,
			ExitDisposition:          "success",
		})
	}
	return 0
}

// entryFor assembles the saved entry. connections is zeroed on kernel: the
// kernel search skips that ladder entirely, so the winner still carries whatever
// baselineParams seeded, and recording it would state a number nothing measured
// and nothing on the kernel transport reads.
func validateEntryForPersist(entry tuning.Entry, softNofile uint64) error {
	if err := tuning.ValidateParams(entry.Params, entry.Transport, nil, softNofile); err != nil {
		return fmt.Errorf("refusing to save tuning the reader would reject: %w", err)
	}
	return nil
}

func entryFor(key tuning.Key, params tuning.Params, measured tuning.Measured) tuning.Entry {
	if key.Transport == "kernel" {
		params.Connections = 0
		params.Slots = 0
		params.MaxOpsPerCompound = 0
	}
	return tuning.Entry{
		Clients:   key.Clients,
		Server:    key.Server,
		Export:    key.Export,
		Transport: key.Transport,
		Params:    params,
		Measured:  measured,
	}
}

// clientSample reads the winner trial's client sample if the runner took one.
func clientSample(runner TrialRunner, host string) (tuning.ClientMeasurement, bool) {
	m, ok := runner.(measuringRunner)
	if !ok {
		return tuning.ClientMeasurement{}, false
	}
	sample, have := m.LastMeasurement()
	if !have {
		return tuning.ClientMeasurement{}, false
	}
	sample.Client = host
	return sample, true
}

// reportPoint prints one measured point, including a failed one.
//
// A failed point's OpsPerSec is legitimately NaN or an infinity -- sweepKnob
// records the point before it decides the trial failed -- so the error, never
// the number, is what a failed point reports.
func reportPoint(out io.Writer, p Point) {
	if p.Err != nil {
		fmt.Fprintf(out, "  %s=%d FAILED: %v\n", p.Knob, p.Value, p.Err)
		return
	}
	fmt.Fprintf(out, "  %s=%d %.0f paths/s\n", p.Knob, p.Value, p.OpsPerSec)
}

// anyMeasured reports whether any point produced a usable rate. An interrupted
// sweep with none of these has measured nothing, and must not be saved.
func anyMeasured(points []Point) bool {
	for _, p := range points {
		if p.Err == nil {
			return true
		}
	}
	return false
}

// persist upserts one entry into the file beside the running binary.
//
// Only an absent file is treated as an empty one. A file that exists but does
// not load is an operator's file this command cannot interpret, and overwriting
// it would destroy every other host/target pair it holds.
func persist(deps commandDeps, path string, entry tuning.Entry, softNofile uint64, out io.Writer) error {
	if err := validateEntryForPersist(entry, softNofile); err != nil {
		return err
	}
	file, err := deps.load(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("existing tuning file %s could not be read (%v); refusing to replace it", path, err)
		}
		file = tuning.File{Version: tuning.Version}
	}
	file.Upsert(entry)
	if err := deps.save(path, file); err != nil {
		return fmt.Errorf("save tuning file: %w", err)
	}
	fmt.Fprintf(out, "wrote %s\n", path)
	return nil
}

func loadRoster(path string) (treegen.Roster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return treegen.Roster{}, fmt.Errorf("reading principals: %w", err)
	}
	var roster treegen.Roster
	if err := json.Unmarshal(data, &roster); err != nil {
		return treegen.Roster{}, fmt.Errorf("parsing principals: %w", err)
	}
	if roster.Domain == "" || len(roster.Roles) == 0 {
		return treegen.Roster{}, fmt.Errorf("principals must have 'domain' and 'roles'")
	}
	return roster, nil
}

type rootRequest struct {
	scratch, serverPath, server, export, transport string
	force, needLocal, needsMount                   bool
}

type resolvedRoots struct {
	localRoot, trialRoot string
	// mount is the zero value when no local path was given: nothing downstream
	// needs a mount in that case, and a separate have-flag would only be a second
	// way to ask the same question.
	mount tuning.Mount
}

// resolveRoots turns the two path flags into the local root and the server-side
// trial root, in the one order that never consults a mount table it does not
// need.
func resolveRoots(deps commandDeps, req rootRequest) (resolvedRoots, error) {
	var roots resolvedRoots
	if req.scratch == "" && req.serverPath == "" {
		return roots, fmt.Errorf("give --scratch (a local path under an NFS mount) or --scratch-server-path (a server-side path under --export)")
	}
	if req.scratch != "" {
		roots.localRoot = filepath.Clean(req.scratch)
	}

	if req.scratch != "" {
		mounts, err := deps.openMounts()
		if err != nil {
			return roots, fmt.Errorf("open /proc/mounts: %w", err)
		}
		mount, err := tuning.ResolveMount(req.scratch, mounts)
		closeErr := mounts.Close()
		if err != nil {
			return roots, fmt.Errorf("resolve --scratch %s: %w", req.scratch, err)
		}
		if closeErr != nil {
			return roots, fmt.Errorf("close /proc/mounts: %w", closeErr)
		}
		if req.server != "" && req.export != "" {
			if err := tuning.MatchExport(mount, req.server, req.export); err != nil {
				return roots, fmt.Errorf("--scratch %s is on the wrong export: %w", req.scratch, err)
			}
		}
		if roots.localRoot == mount.MountPoint {
			return roots, fmt.Errorf("--scratch %s is the mount point itself; give a subdirectory so generation and repair cannot touch the export root", req.scratch)
		}
		derived, err := tuning.ServerPath(roots.localRoot, mount)
		if err != nil {
			return roots, fmt.Errorf("derive the server-side path of --scratch %s: %w", req.scratch, err)
		}
		roots.mount = mount
		roots.trialRoot = derived
	}

	if req.serverPath != "" {
		if !filepath.IsAbs(req.serverPath) {
			return roots, fmt.Errorf("--scratch-server-path %s must be an absolute server-side path", req.serverPath)
		}
		given := filepath.Clean(req.serverPath)
		if roots.trialRoot != "" && given != roots.trialRoot {
			return roots, fmt.Errorf("--scratch %s resolves to server path %s, but --scratch-server-path says %s; they must name the same tree",
				req.scratch, roots.trialRoot, given)
		}
		roots.trialRoot = given
	}

	if req.export != "" && roots.trialRoot == filepath.Clean(req.export) {
		return roots, fmt.Errorf("the trial tree is the export root %s; give a subdirectory so generation and repair cannot touch it", req.export)
	}

	if req.needLocal && roots.localRoot == "" {
		return roots, fmt.Errorf("--scratch is required here: %s needs a local mount path, and only --scratch-server-path was given",
			localPathConsumers(req))
	}
	return roots, nil
}

// localPathConsumers names every reason a local path is required, so an operator
// can tell a fixable flag from a fixable configuration.
func localPathConsumers(req rootRequest) string {
	var reasons []string
	if req.needsMount {
		reasons = append(reasons, "the tree generation backend")
	}
	if req.transport == "kernel" {
		reasons = append(reasons, "the kernel transport")
	}
	if req.force {
		reasons = append(reasons, "--force, which counts entries locally")
	}
	if len(reasons) == 0 {
		return "this configuration"
	}
	joined := reasons[0]
	for _, r := range reasons[1:] {
		joined += " and " + r
	}
	return joined
}
