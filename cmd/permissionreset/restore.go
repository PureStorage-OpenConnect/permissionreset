package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/idmap"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/restore"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/signals"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// restoreConflicts are the flags --restore-from refuses rather than ignores
// (docs/design-acl-restore.md section 3).
var restoreConflicts = []struct{ flag, why string }{
	{"spec", "the reference tree is the source of truth; there is no spec"},
	{"sacl", "a restore writes the reference's audit ACEs as they are"},
	{"accept-dacl-flattening", "it applies to a spec's sacl:-only rules; a restore has none"},
	{"set-owner", "system.nfs4_acl carries no owner or group, and a restore does not change them"},
	{"compare", "a restore always compares, byte for byte"},
	{"skip-identity-check", "a restore has no spec principals to resolve"},
	{"pfind", "a restore walks both trees together"},
	{"no-pfind", "a restore walks both trees together"},
	{"batch-size", "a restore does not batch"},
	{"audit-log", "deprecated; use --evidence-dir"},
	{"server", "a restore runs on the kernel transport only"},
	{"export", "a restore runs on the kernel transport only"},
	{"connections", "a restore runs on the kernel transport only"},
	{"slots", "a restore runs on the kernel transport only"},
	{"max-ops-per-compound", "a restore runs on the kernel transport only"},
	{"rpc-timeout", "a restore runs on the kernel transport only"},
	{"retry-budget", "a restore runs on the kernel transport only"},
	{"retry-base-delay", "a restore runs on the kernel transport only"},
	{"auth-uid", "a restore runs on the kernel transport only"},
	{"auth-gid", "a restore runs on the kernel transport only"},
	{"auth-gids", "a restore runs on the kernel transport only"},
	{"auth-hostname", "a restore runs on the kernel transport only"},
	{"rpc-stats", "a restore runs on the kernel transport only"},
	{"allow-high-ids", "a restore refuses each object naming an id at or above 1000000000, and no flag lifts that: the refusal protects a SID"},
}

// referenceWritable is a seam: whether the reference root accepts writes, and
// how that was decided.
//
// It tries the write: create a probe file in the reference root, and remove it
// if that worked. Only EROFS counts as read-only. access(W_OK) and statvfs
// cannot answer this on FlashBlade: NFS ACCESS is answered from the ACL, so
// access(2) says a snapshot is writable, and each snapshot is its own
// read-write submount, so ST_RDONLY is clear -- yet every write to it fails
// EROFS (lab, Purity//FB 4.8.7). A no-op ACL write is not used as the probe:
// on a reference that is in fact writable, and on FlashArray, an NFS ACL write
// flattens SMB inheritance even with identical bytes (RISKS.md #11). Creating
// and removing an empty file touches no ACL. Any other failure (EACCES, say)
// cannot tell, and is treated as writable.
var referenceWritable = func(dir string) (bool, string) {
	f, err := os.CreateTemp(dir, ".permissionreset-refprobe-")
	if err == nil {
		name := f.Name()
		f.Close()
		if rerr := os.Remove(name); rerr != nil {
			return true, fmt.Sprintf("created probe %s and could not remove it (%v); remove it by hand", name, rerr)
		}
		return true, "a probe file could be created in it (and was removed)"
	}
	if errors.Is(err, unix.EROFS) {
		return false, "read-only (EROFS)"
	}
	return true, fmt.Sprintf("could not tell (%v), so it is treated as writable", err)
}

// runRestore is --restore-from REF TARGET.
func runRestore(f *flags, pf *preflightResult, out, errOut io.Writer) (exitCode int) {
	for _, c := range restoreConflicts {
		if pf.explicit[c.flag] {
			fmt.Fprintf(errOut, "ERROR: --%s cannot be used with --restore-from: %s\n", c.flag, c.why)
			return 1
		}
	}
	if *f.transportName != "kernel" {
		fmt.Fprintf(errOut, "ERROR: --restore-from needs --transport=kernel (got %s); there is no userspace restore\n", *f.transportName)
		return 1
	}

	mode := restore.DryRun
	switch {
	case *f.validate:
		mode = restore.Validate
	case *f.applyFlag && !*f.dryRun:
		mode = restore.Apply
	}
	if *f.resume && *f.ckptPath == "" {
		fmt.Fprintln(errOut, "ERROR: --resume requires --checkpoint")
		return 1
	}
	if *f.ckptPath != "" && mode != restore.Apply {
		fmt.Fprintf(errOut, "ERROR: --checkpoint needs --apply; a restore %s keeps no state\n", mode)
		return 1
	}
	if *f.workers < 1 || *f.workers > 8192 {
		fmt.Fprintf(errOut, "ERROR: --workers must be between 1 and 8192, got %d\n", *f.workers)
		return 1
	}

	ref, err := targetForKernel(*f.restoreFrom)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: --restore-from: %v\n", err)
		return 1
	}
	target, err := targetForKernel(pf.target)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	if err := checkRootsDisjoint(ref, target); err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	excluder, err := spec.NewExcluder(target, pf.excludes)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: --exclude: %v\n", err)
		return 1
	}

	refT, err := transport.NewKernel(ref)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	liveT, err := transport.NewKernel(target)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	evOpts, err := evidenceOptions(f, errOut)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	lh, err := setupLogging(*f.logPath)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}
	if lh.logFile != nil {
		defer func() {
			if err := lh.logFile.Close(); err != nil {
				fmt.Fprintf(errOut, "ERROR: close log %s: %v\n", *f.logPath, err)
				if exitCode == 0 {
					exitCode = 1
				}
			}
		}()
	}
	sink, err := openSink(evOpts, newRunID())
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	var ckpt *checkpoint.Checkpoint
	if *f.ckptPath != "" {
		ckpt, err = checkpoint.Open(*f.ckptPath, checkpoint.RestoreHash(ref, target, version, pf.excludes, *f.oneFilesystem), *f.resume)
		if err != nil {
			if sink != nil {
				sink.Close(false, "checkpoint open failed")
			}
			fmt.Fprintf(errOut, "ERROR: checkpoint: %v\n", err)
			return 1
		}
	}

	// With --allow-writable-reference the probe's answer changes nothing, so it
	// is not run: no file is created in the reference for no reason.
	writable := false
	if mode == restore.Apply && !*f.allowWritableRef {
		var how string
		writable, how = referenceWritable(ref)
		fmt.Fprintf(errOut, "NOTE: reference write probe: %s\n", how)
	}

	cfg := restore.Config{
		Reference: ref, Target: target, Ref: refT, Live: liveT, Mode: mode, Workers: *f.workers,
		Excluder: excluder, Excludes: pf.excludes, OneFilesystem: *f.oneFilesystem, ReplacedCheck: true,
		Checkpoint: ckpt, Evidence: sink,
		AllowAuditedDACLReset: *f.allowAudited, AllowAuditRemoval: *f.allowAuditRemoval,
		AllowWritableReference: *f.allowWritableRef, ReferenceWritable: writable,
		Resolver: idmap.NewNSS(),
	}
	if lh.logFile != nil {
		cfg.Log = lh.logOut
	}

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

	res, runErr := restoreCommand(ctx, cfg, out, errOut)
	close(runDone)
	<-sigMessageDone

	exitCode = 0
	if runErr != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", runErr)
		exitCode = 1
	} else if !res.OK() {
		exitCode = 1
	}
	if ckpt != nil {
		if err := ckpt.Close(); err != nil {
			fmt.Fprintf(errOut, "ERROR: checkpoint %s could not be flushed: %v; delete it before resuming\n", *f.ckptPath, err)
			exitCode = 3
		}
	}
	if res.Evidence != nil {
		fmt.Fprintf(out, "  Evidence:         %s (%s)\n", evidenceDirOf(evOpts), res.Evidence.Status)
	}
	if *f.jsonSummary != "" {
		data, err := json.MarshalIndent(struct {
			Tool     string `json:"tool"`
			Version  string `json:"version"`
			Commit   string `json:"commit"`
			ExitCode int    `json:"exit_code"`
			restore.Result
		}{"permissionreset", version, commit, exitCode, res}, "", "  ")
		if err == nil {
			err = os.WriteFile(*f.jsonSummary, append(data, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: write JSON summary: %v\n", err)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}
	if mode == restore.DryRun && runErr == nil {
		fmt.Fprintln(out, "\nDry run: nothing was written. Re-run with --validate to compare, or --apply to restore.")
	}
	return exitCode
}

// restoreCommand is a seam, like runCommand.
var restoreCommand = restore.Run

// checkRootsDisjoint refuses a reference and target that are the same
// directory or where one contains the other. Both are already resolved.
func checkRootsDisjoint(ref, target string) error {
	if ref == target {
		return fmt.Errorf("--restore-from %s and the target are the same directory", ref)
	}
	within := func(a, b string) bool { // a is b or under it
		rel, err := filepath.Rel(b, a)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
	}
	if within(ref, target) {
		return fmt.Errorf("--restore-from %s is inside the target %s", ref, target)
	}
	if within(target, ref) {
		return fmt.Errorf("the target %s is inside --restore-from %s", target, ref)
	}
	return nil
}
