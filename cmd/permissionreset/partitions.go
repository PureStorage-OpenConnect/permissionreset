package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/partition"
	runpkg "github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/signals"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/summary"
)

// ReportName is the aggregate report runPartitioned writes into the state
// directory after every invocation.
const ReportName = "report.json"

// partitionConflicts are the flags a manifest supplies, or that would point
// every partition's files at one place. Each is refused rather than ignored.
var partitionConflicts = []struct{ flag, why string }{
	{"spec", "the manifest names the spec"},
	{"exclude", "the manifest's exclude: list is part of every partition's binding"},
	{"checkpoint", "each partition keeps its checkpoint in the state directory"},
	{"evidence-dir", "each attempt keeps its evidence in the state directory"},
	{"audit-log", "each attempt keeps its evidence in the state directory"},
	{"log", "each attempt keeps its error log in the state directory"},
	{"pfind", "pfind cannot prune a handed-off partition root"},
}

// runPartitioned is --partitions: load the manifest, check it against the
// tree, and run each partition through the same path a single TARGET takes.
func runPartitioned(fs *flag.FlagSet, f *flags, pf *preflightResult, out, errOut io.Writer) int {
	if fs.NArg() > 0 {
		fmt.Fprintf(errOut, "ERROR: --partitions takes no TARGET (got %q); the manifest names the root\n", fs.Arg(0))
		return 1
	}
	for _, c := range partitionConflicts {
		if pf.explicit[c.flag] {
			fmt.Fprintf(errOut, "ERROR: --%s cannot be used with --partitions: %s\n", c.flag, c.why)
			return 1
		}
	}
	plan, err := partition.Load(*f.partitions)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	mode := partition.ModeApply
	switch {
	case *f.validate:
		mode = partition.ModeValidate
	case *f.dryRun || !*f.applyFlag:
		mode = partition.ModeDryRun
	}
	if mode == partition.ModeDryRun && *f.resume {
		fmt.Fprintln(errOut, "ERROR: --resume needs --apply or --validate; a dry run keeps no partition state")
		return 1
	}

	// Every partition root is canonicalized up front, so a bad one is refused
	// before the first partition writes anything. On the kernel transport the
	// canonical path must be the manifest's: a root reached through a symlink
	// is an alias, and the residual's handoff is by exact path.
	for _, j := range plan.Jobs {
		got, err := validateTransport(j.Root, f, plan.Spec, plan.Manifest.Exclude, pf.explicit, pf.workersTyped, errOut)
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: partition %q\n", j.Name)
			return 1
		}
		if got != j.Root {
			fmt.Fprintf(errOut, "ERROR: partition %q: %s resolves to %s; name the resolved path in the manifest\n", j.Name, j.Root, got)
			return 1
		}
	}
	var ids map[string]partition.Identity
	if *f.transportName == "kernel" {
		if ids, err = partition.CheckIdentity(plan, *f.oneFilesystem); err != nil {
			fmt.Fprintf(errOut, "ERROR: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(errOut, "NOTE: --transport=userspace: partition roots are not checked for aliases "+
			"(bind mounts, a second mount of one export) or for replacement between attempts; "+
			"those checks need a local stat")
	}

	fmt.Fprintf(out, "Partition manifest: %s (sha256 %s)\n", plan.Path, plan.Digest)
	fmt.Fprintf(out, "  Root:       %s\n", plan.Root)
	fmt.Fprintf(out, "  Spec:       %s\n", plan.SpecPath)
	fmt.Fprintf(out, "  Mode:       %s\n", mode)
	if mode != partition.ModeDryRun {
		fmt.Fprintf(out, "  State:      %s\n", plan.StateDir)
	}
	fmt.Fprintf(out, "  Partitions: %d listed, plus %s (everything else under the root)\n", len(plan.Jobs)-1, partition.ResidualName)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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

	rep, err := partition.Execute(ctx, plan, partition.Options{
		Mode: mode, Resume: *f.resume, Only: *f.partitionOnly, ToolVersion: version,
		Identities: ids, Out: out,
	}, func(ctx context.Context, job partition.Job, paths partition.AttemptPaths) (runpkg.Result, int, error) {
		return runPartition(ctx, plan, job, paths, f, pf, out, errOut)
	})
	close(runDone)
	<-sigMessageDone
	if rep == nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	printReport(out, rep)
	code := 0
	if err != nil {
		code = 1
	}
	if mode != partition.ModeDryRun {
		if werr := writeReport(filepath.Join(plan.StateDir, ReportName), rep); werr != nil {
			fmt.Fprintf(errOut, "ERROR: write report: %v\n", werr)
			code = 1
		}
	}
	if *f.jsonSummary != "" {
		if werr := writeReport(*f.jsonSummary, rep); werr != nil {
			fmt.Fprintf(errOut, "ERROR: write JSON summary: %v\n", werr)
			code = 1
		} else {
			fmt.Fprintf(out, "  Summary:    %s\n", *f.jsonSummary)
		}
	}
	return code
}

// runPartition runs one partition: the same spec load, log, evidence,
// buildConfig and summary a single-TARGET run uses, pointed at the job.
func runPartition(ctx context.Context, plan *partition.Plan, job partition.Job, paths partition.AttemptPaths,
	f *flags, pf *preflightResult, out, errOut io.Writer) (runpkg.Result, int, error) {
	start := time.Now()
	specDigest, _ := summary.FileDigest(plan.SpecPath)

	*f.evidenceDir = paths.EvidenceDir
	evOpts, err := evidenceOptions(f, errOut)
	if err != nil {
		return runpkg.Result{}, 1, err
	}
	lh, err := setupLogging(paths.ErrorLog)
	if err != nil {
		return runpkg.Result{}, 1, err
	}
	closeLog := func() error {
		if lh.logFile == nil {
			return nil
		}
		return lh.logFile.Close()
	}
	runID := newRunID()
	sink, err := openSink(evOpts, runID)
	if err != nil {
		closeLog()
		return runpkg.Result{}, 1, err
	}

	*f.specPath, *f.ckptPath, *f.resume = plan.SpecPath, paths.Checkpoint, paths.Resume
	bcr, err := buildConfig(job.Root, plan.Spec, plan.Manifest.Exclude, pf.explicit, pf.workersTyped, pf.authCred, lh.logOut, sink, f, out, errOut)
	if err != nil {
		closeLog()
		return runpkg.Result{}, 1, err
	}
	cfg := bcr.cfg
	cfg.ExcludeRoot = plan.Root
	cfg.Handoff = job.Handoff

	res, runErr := runCommand(ctx, cfg, out)
	if runErr != nil {
		if errors.Is(runErr, runpkg.ErrCheckpointUnflushed) && paths.Checkpoint != "" {
			// The checkpoint no longer describes the partition, and the next
			// attempt would otherwise resume from it. Set it aside: the next
			// attempt starts the partition fresh.
			aside := fmt.Sprintf("%s.untrusted-%d", paths.Checkpoint, time.Now().Unix())
			if err := os.Rename(paths.Checkpoint, aside); err == nil {
				fmt.Fprintf(errOut, "NOTE: checkpoint set aside as %s; the next attempt starts partition %q fresh\n", aside, job.Name)
			} else {
				fmt.Fprintf(errOut, "ERROR: set aside untrusted checkpoint %s: %v; delete it before resuming\n", paths.Checkpoint, err)
			}
		} else {
			reportTraverseNotPreserved(errOut, runErr)
		}
	}
	code := exitCodeFor(runErr)
	jsonPath := ""
	if paths.ErrorLog != "" {
		jsonPath = filepath.Join(filepath.Dir(paths.ErrorLog), "summary.json")
	}
	_, code = buildSummary(res, code, buildSummaryOpts{
		target: job.Root, transportName: *f.transportName, server: *f.server, export: *f.export,
		specPath: plan.SpecPath, specDigest: specDigest, batchSize: *f.batchSize,
		connections: *f.connections, oneFilesystem: *f.oneFilesystem, ckptPath: paths.Checkpoint,
		resume: paths.Resume, logPath: paths.ErrorLog, evidenceDir: paths.EvidenceDir, runID: runID,
		setOwner: *f.setOwner, jsonSummary: jsonPath, runStart: start, s: plan.Spec, validate: *f.validate,
	})
	if err := closeLog(); err != nil {
		fmt.Fprintf(errOut, "ERROR: close log %s: %v\n", paths.ErrorLog, err)
		if code == 0 {
			code = 1
		}
	}
	return res, code, runErr
}

func writeReport(path string, rep *partition.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func printReport(out io.Writer, rep *partition.Report) {
	fmt.Fprintln(out, "\nPartitions:")
	for _, ps := range rep.Partitions {
		line := fmt.Sprintf("  %-20s %-9s attempts %d", ps.Name, ps.Status, len(ps.Attempts))
		if n := len(ps.Attempts); n > 0 {
			a := ps.Attempts[n-1]
			line += fmt.Sprintf("  enumerated %d applied %d skipped %d failed %d", a.Counts.Enumerated, a.Counts.Applied, a.Counts.Skipped, a.Counts.Failed)
			if a.EvidenceStatus != "" {
				line += "  evidence " + a.EvidenceStatus
			}
		}
		fmt.Fprintln(out, line)
	}
	t := rep.Totals
	fmt.Fprintln(out, "Totals (every attempt):")
	fmt.Fprintf(out, "  Enumerated: %d  Applied: %d  Skipped: %d  Symlinks: %d  Excluded: %d  Failed: %d  Errors: %d\n",
		t.Enumerated, t.Applied, t.Skipped, t.Symlinks, t.Excluded, t.Failed, t.TotalErrors)
	if rep.Mode == partition.ModeValidate {
		fmt.Fprintf(out, "  Match: %d  Mismatch: %d  Unreadable: %d\n", t.Match, t.Mismatch, t.Unreadable)
	}
	if len(rep.UncountedAttempts) > 0 {
		fmt.Fprintf(out, "  NOTE: totals are a lower bound; attempt(s) %s died before recording counts. Run --validate for exact coverage.\n",
			strings.Join(rep.UncountedAttempts, ", "))
	}
	if rep.Complete {
		fmt.Fprintln(out, "Result: complete")
	} else {
		fmt.Fprintln(out, "Result: INCOMPLETE")
		for _, r := range rep.Reasons {
			fmt.Fprintf(out, "  - %s\n", r)
		}
		for _, u := range rep.Unreached {
			fmt.Fprintf(out, "  - unreached partition root: %s\n", u)
		}
		if rep.Mode != partition.ModeDryRun {
			fmt.Fprintln(out, "  Re-run with --resume to retry what did not complete.")
		}
	}
}
