package partition

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
)

// Mode values.
const (
	ModeApply    = "apply"
	ModeValidate = "validate"
	ModeDryRun   = "dry-run"
)

// AttemptPaths is where one attempt keeps its files. Empty fields are off.
type AttemptPaths struct {
	// Checkpoint is per partition, shared by its attempts: that is what lets a
	// failed partition resume instead of restarting.
	Checkpoint string
	// Resume is whether Checkpoint holds an earlier attempt's progress.
	Resume bool
	// EvidenceDir and ErrorLog are per attempt: an evidence directory must be
	// new, and an earlier attempt's records are kept as what happened.
	EvidenceDir string
	ErrorLog    string
}

// RunFunc runs one job. The command supplies it, building a run.Config from
// its own flags plus the job; tests supply a fake.
type RunFunc func(ctx context.Context, job Job, paths AttemptPaths) (run.Result, int, error)

// Options configure Execute.
type Options struct {
	Mode        string
	Resume      bool
	Only        []string // run only these partitions; the rest are left as they are
	ToolVersion string
	// Identities is CheckIdentity's result, or nil on the userspace transport.
	Identities map[string]Identity
	Out        io.Writer
}

// Report is the aggregate: every partition's latest status and the sum of
// every attempt's counts.
type Report struct {
	Mode           string      `json:"mode"`
	ManifestPath   string      `json:"manifest"`
	ManifestDigest string      `json:"manifest_sha256"`
	Root           string      `json:"root"`
	StateDir       string      `json:"state_dir,omitempty"`
	Partitions     []PartState `json:"partitions"`
	// Totals sums Counts over every attempt of every partition. An object a
	// resumed attempt re-examined is in two attempts' counts, as it was in two
	// runs; Totals reconcile with the attempts exactly, not with the tree.
	Totals Counts `json:"totals"`
	// UncountedAttempts names ("partition#n") the attempts whose process died
	// before recording counts. When any are listed, Totals are a lower bound:
	// they omit what those attempts did. A later --validate gives exact
	// per-object coverage.
	UncountedAttempts []string `json:"uncounted_attempts,omitempty"`
	// Complete is true when every partition is complete and the residual
	// reached every partition root.
	Complete bool `json:"complete"`
	// Reasons says why Complete is false.
	Reasons []string `json:"reasons,omitempty"`
	// Unreached is the partition roots no residual attempt handed off.
	Unreached []string `json:"unreached,omitempty"`
	// EvidenceComplete is true when evidence is on and every partition's
	// final attempt closed its evidence complete.
	EvidenceComplete bool `json:"evidence_complete"`
	// IncompleteEvidenceAttempts counts attempts, final or superseded, whose
	// evidence closed incomplete. Superseded ones are kept: they are the record
	// of what those attempts changed.
	IncompleteEvidenceAttempts int `json:"incomplete_evidence_attempts"`
}

// ErrIncomplete is returned when at least one partition did not complete.
var ErrIncomplete = errors.New("partitioned run incomplete")

// Execute runs the plan's jobs one at a time, residual first, and returns the
// aggregate. A dry run keeps no state and runs everything. Apply and validate
// keep a state file in the plan's state_dir: without Resume an existing state
// is refused, and with it completed partitions are skipped and every other
// partition is run again, resuming its checkpoint when it has one.
//
// A failed partition does not stop the others; its siblings' results are
// independent of it. Cancellation does: the partition in flight is recorded as
// failed and nothing after it starts.
func Execute(ctx context.Context, p *Plan, o Options, runOne RunFunc) (*Report, error) {
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	for _, name := range o.Only {
		if p.Job(name) == nil {
			return nil, fmt.Errorf("--partition %q: no such partition in %s (have %s)", name, p.Path, jobNames(p))
		}
	}

	var st *State
	if o.Mode == ModeDryRun {
		st = newState(p, o.Mode, o.ToolVersion, o.Identities)
	} else {
		if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
			return nil, err
		}
		release, err := lockDir(p.StateDir)
		if err != nil {
			return nil, err
		}
		defer release()
		if st, err = openState(p, o); err != nil {
			return nil, err
		}
	}
	save := func() error {
		if o.Mode == ModeDryRun {
			return nil
		}
		return st.save(p.StateDir)
	}
	if err := save(); err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}

	for _, job := range p.Jobs {
		ps := st.part(job.Name)
		if len(o.Only) > 0 && !slices.Contains(o.Only, job.Name) {
			continue
		}
		if ps.Status == StatusComplete {
			fmt.Fprintf(out, "\n=== partition %s: complete in attempt %d, skipped ===\n", job.Name, len(ps.Attempts))
			continue
		}
		if ctx.Err() != nil {
			break
		}
		a := Attempt{N: len(ps.Attempts) + 1, Started: time.Now().UTC()}
		paths := attemptPaths(p, o.Mode, job.Name, a.N)
		paths.Resume = o.Mode == ModeApply && hasCheckpoint(ps)
		a.Resumed = paths.Resume
		a.Checkpoint, a.EvidenceDir, a.ErrorLog = paths.Checkpoint, paths.EvidenceDir, paths.ErrorLog
		if paths.EvidenceDir != "" || paths.ErrorLog != "" {
			if err := os.MkdirAll(filepath.Join(p.StateDir, job.Name, fmt.Sprintf("attempt-%d", a.N)), 0o755); err != nil {
				return nil, err
			}
		}
		ps.Status = StatusRunning
		ps.Attempts = append(ps.Attempts, a)
		if err := save(); err != nil {
			return nil, fmt.Errorf("write state: %w", err)
		}

		resuming := ""
		if paths.Resume {
			resuming = ", resuming checkpoint"
		}
		fmt.Fprintf(out, "\n=== partition %s (%s), attempt %d%s ===\n", job.Name, job.Root, a.N, resuming)
		res, code, err := runOne(ctx, job, paths)
		a = ps.Attempts[len(ps.Attempts)-1]
		recordAttempt(&a, job, res, code, err)
		ps.Attempts[len(ps.Attempts)-1] = a
		if len(a.Reasons) == 0 {
			ps.Status = StatusComplete
		} else {
			ps.Status = StatusFailed
		}
		if err := save(); err != nil {
			return nil, fmt.Errorf("write state: %w", err)
		}
		fmt.Fprintf(out, "=== partition %s: %s ===\n", job.Name, ps.Status)
	}

	rep := aggregate(p, st, o.Mode)
	if !rep.Complete {
		return rep, ErrIncomplete
	}
	return rep, nil
}

func jobNames(p *Plan) string {
	var s string
	for i, j := range p.Jobs {
		if i > 0 {
			s += ", "
		}
		s += j.Name
	}
	return s
}

func openState(p *Plan, o Options) (*State, error) {
	prev, err := loadState(p.StateDir)
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(p.StateDir, StateName)
	if prev == nil {
		if o.Resume {
			return nil, fmt.Errorf("--resume: no %s; nothing to resume", statePath)
		}
		return newState(p, o.Mode, o.ToolVersion, o.Identities), nil
	}
	if !o.Resume {
		return nil, fmt.Errorf("%s already records a partitioned run; pass --resume to continue it, or give the manifest a new state_dir", statePath)
	}
	switch {
	case prev.ManifestDigest != p.Digest:
		return nil, fmt.Errorf("%s was written for a different manifest (sha256 %s, now %s); a changed manifest redraws the partitions, so give it a new state_dir",
			statePath, prev.ManifestDigest, p.Digest)
	case prev.Mode != o.Mode:
		return nil, fmt.Errorf("%s records a %s run; it cannot be resumed as %s", statePath, prev.Mode, o.Mode)
	case prev.ToolVersion != o.ToolVersion:
		return nil, fmt.Errorf("%s was written by permissionreset %s, this is %s; checkpoints are bound to the tool version, so give the manifest a new state_dir",
			statePath, prev.ToolVersion, o.ToolVersion)
	}
	if (prev.Identities == nil) != (o.Identities == nil) {
		return nil, fmt.Errorf("%s was written on another transport (identities recorded: %t)", statePath, prev.Identities != nil)
	}
	for name, was := range prev.Identities {
		if now, ok := o.Identities[name]; !ok || now != was {
			return nil, fmt.Errorf("partition %q: its root is no longer the same directory (device/inode %d/%d, now %d/%d); it was renamed or replaced since the run began",
				name, was.Dev, was.Ino, now.Dev, now.Ino)
		}
	}
	for i := range prev.Partitions {
		// A partition left running was in flight when the process died.
		if prev.Partitions[i].Status == StatusRunning {
			prev.Partitions[i].Status = StatusFailed
			at := &prev.Partitions[i].Attempts[len(prev.Partitions[i].Attempts)-1]
			at.Reasons = append(at.Reasons, "the driver stopped while this attempt was running")
			at.ExitCode = -1
			at.Uncounted = true
		}
	}
	return prev, nil
}

func attemptPaths(p *Plan, mode, name string, n int) AttemptPaths {
	if mode == ModeDryRun {
		return AttemptPaths{}
	}
	dir := filepath.Join(p.StateDir, name)
	adir := filepath.Join(dir, fmt.Sprintf("attempt-%d", n))
	var ap AttemptPaths
	if mode == ModeApply {
		ap.Checkpoint = filepath.Join(dir, "checkpoint")
	}
	ap.ErrorLog = filepath.Join(adir, "errors.log")
	if p.Evidence {
		ap.EvidenceDir = filepath.Join(adir, "evidence")
	}
	return ap
}

// hasCheckpoint is whether an earlier attempt left a checkpoint to resume. An
// attempt that failed before Run opened it leaves no file, and resuming a
// missing checkpoint is an error, so the file is asked rather than assumed.
func hasCheckpoint(ps *PartState) bool {
	for _, a := range ps.Attempts {
		if a.Checkpoint != "" {
			if _, err := os.Stat(a.Checkpoint); err == nil {
				return true
			}
		}
	}
	return false
}

// recordAttempt folds one run's result into its attempt and decides whether it
// completed the partition. Every reason is kept, not just the first.
func recordAttempt(a *Attempt, job Job, res run.Result, code int, err error) {
	a.Ended = time.Now().UTC()
	a.ExitCode = code
	if err != nil {
		a.Error = err.Error()
		a.Reasons = append(a.Reasons, "run failed: "+err.Error())
	} else if code != 0 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("exit code %d", code))
	}
	st := res.Stats
	a.Counts = Counts{
		Enumerated: st.Enumerated, Applied: st.Applied, Skipped: st.Skipped, Symlinks: st.Symlinks,
		Excluded: st.Excluded, Failed: st.Errors, Match: res.MatchCount, Mismatch: res.MismatchCount,
		Unreadable: res.UnreadableCount, NotAttempted: res.NotAttempted, TotalErrors: res.TotalErrors,
	}
	a.Interrupted = res.Interrupted
	a.EnumerationComplete = res.WalkErrors == 0 && res.ReaddirErrors == 0 && !res.Interrupted &&
		res.DuplicateCompletions == 0 && !res.EvidenceStopped
	a.HandedOff = res.HandedOff
	if !a.EnumerationComplete {
		a.Reasons = append(a.Reasons, "enumeration incomplete")
	}
	if res.TotalErrors > 0 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("%d errors", res.TotalErrors))
	}
	if res.MismatchCount > 0 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("%d mismatches", res.MismatchCount))
	}
	if a.EvidenceDir != "" {
		if m := res.Evidence; m != nil {
			a.EvidenceStatus, a.EvidenceRecords = m.Status, m.RecordsWritten
		} else {
			a.EvidenceStatus = evidence.StatusIncomplete
		}
		if a.EvidenceStatus != evidence.StatusComplete {
			a.Reasons = append(a.Reasons, "evidence incomplete")
		}
	}
	// A residual attempt that resumed may legitimately skip a completed
	// ancestor and with it a handoff, so reachability is judged across
	// attempts by aggregate, not here; a handoff reached twice in one attempt
	// is a walk bug and is refused here.
	if len(job.Handoff) > 0 && len(slices.Compact(slices.Clone(res.HandedOff))) != len(res.HandedOff) {
		a.Reasons = append(a.Reasons, "a partition root was handed off twice")
	}
}

func aggregate(p *Plan, st *State, mode string) *Report {
	rep := &Report{
		Mode: mode, ManifestPath: p.Path, ManifestDigest: p.Digest, Root: p.Root,
		Partitions: st.Partitions, Complete: true, EvidenceComplete: p.Evidence && mode != ModeDryRun,
	}
	if mode != ModeDryRun {
		rep.StateDir = p.StateDir
	}
	for _, ps := range st.Partitions {
		for _, a := range ps.Attempts {
			rep.Totals.add(a.Counts)
			if a.Uncounted {
				rep.UncountedAttempts = append(rep.UncountedAttempts, fmt.Sprintf("%s#%d", ps.Name, a.N))
			}
			if a.EvidenceDir != "" && a.EvidenceStatus != evidence.StatusComplete {
				rep.IncompleteEvidenceAttempts++
			}
		}
		if ps.Status != StatusComplete {
			rep.Complete = false
			rep.Reasons = append(rep.Reasons, fmt.Sprintf("partition %s is %s", ps.Name, ps.Status))
		}
		if n := len(ps.Attempts); n == 0 || ps.Attempts[n-1].EvidenceStatus != evidence.StatusComplete {
			rep.EvidenceComplete = false
		}
	}
	// Every partition root must have been reached by some residual attempt. A
	// root the residual never reached was pruned by something else first -- a
	// --one-filesystem boundary, an unreadable ancestor -- and the partition
	// beneath it, however clean its own run, is not part of the tree the
	// residual walked.
	reached := map[string]bool{}
	res := st.part(ResidualName)
	for _, a := range res.Attempts {
		for _, h := range a.HandedOff {
			reached[h] = true
		}
	}
	for _, j := range p.Jobs[1:] {
		if !reached[j.Root] {
			rep.Unreached = append(rep.Unreached, j.Root)
		}
	}
	if len(rep.Unreached) > 0 && res.Status == StatusComplete {
		rep.Complete = false
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("the residual walk never reached %d partition root(s)", len(rep.Unreached)))
	}
	return rep
}
