package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
)

// probeCopies is the size of the calibration tree. It is small enough to build
// in seconds at any plausible rate and large enough that per-copy cost is not
// dominated by the first subtree's directory creation.
const probeCopies = 4

// minTrialDuration is the shortest trial the sweeper will accept. Below this,
// session setup and the first readdir round trips are a large enough share of
// the measurement that knob effects disappear into the noise.
const minTrialDuration = 10 * time.Second

// baselineTrialFunc measures stock-parameter throughput over a root, in
// paths/sec. During sizing its only use is extrapolation; the drift baseline
// the search compares against is measured later, on the full tree.
type baselineTrialFunc func(context.Context, string) (float64, error)

// ScratchProvisioner is the generation seam. Its NeedsLocalMount answer — not
// the transport name — decides whether a local mount path is required.
// posixProvisioner is the only implementation built here and returns true; a
// future userspace provisioner returns false and changes nothing above this
// interface.
type ScratchProvisioner interface {
	Probe(ctx context.Context, shape treegen.Config) error
	Provision(ctx context.Context, shape treegen.Config) error
	Inspect(ctx context.Context) (treegen.Manifest, bool, error)
	EnumerateCount(ctx context.Context) (int64, error) // --force path
	Remove(ctx context.Context) error                  // proven generated trees only
	NeedsLocalMount() bool
}

// posixProvisioner wraps treegen.RunContext, treegen.ReadManifest and a local
// walk. It is the kernel-mount backend: everything it does assumes the tree is
// reachable as an ordinary directory.
type posixProvisioner struct {
	localRoot        string
	base             treegen.Config
	out              io.Writer
	removeAll        func(string) error
	now              func() time.Time
	progressInterval time.Duration
}

func newPosixProvisioner(localRoot string, base treegen.Config) *posixProvisioner {
	base.Target = localRoot
	return &posixProvisioner{
		localRoot:        localRoot,
		base:             base,
		out:              os.Stdout,
		removeAll:        os.RemoveAll,
		now:              time.Now,
		progressInterval: 10 * time.Second,
	}
}

func (p *posixProvisioner) NeedsLocalMount() bool { return true }

func (p *posixProvisioner) config(shape treegen.Config) treegen.Config {
	cfg := p.base
	cfg.Target = p.localRoot
	cfg.Scale = shape.Scale
	cfg.Seed = shape.Seed
	cfg.FilesPerSubtree = shape.FilesPerSubtree
	if shape.Workers > 0 {
		cfg.Workers = shape.Workers
	}
	if shape.SafetyPrincipal != "" {
		cfg.SafetyPrincipal = shape.SafetyPrincipal
	}
	if shape.Roster.Domain != "" {
		cfg.Roster = shape.Roster
	}
	return cfg
}

func (p *posixProvisioner) Probe(ctx context.Context, shape treegen.Config) error {
	return treegen.RunContext(ctx, p.config(shape))
}

func (p *posixProvisioner) Provision(ctx context.Context, shape treegen.Config) error {
	return treegen.RunContext(ctx, p.config(shape))
}

func (p *posixProvisioner) Inspect(ctx context.Context) (treegen.Manifest, bool, error) {
	m, err := treegen.ReadManifest(p.localRoot)
	if os.IsNotExist(err) {
		return treegen.Manifest{}, false, nil
	}
	if err != nil {
		return treegen.Manifest{}, false, err
	}
	return m, true, nil
}

// EnumerateCount counts non-symlink entries below the root. It is the --force
// fallback for a tree the sweeper cannot prove it generated, so it must never
// follow a link out of the tree.
//
// A read error is returned, never absorbed: a zero count is what authorizes
// generating into the root, and under --force it is the trial size itself. An
// unreadable directory is not an empty one.
func (p *posixProvisioner) EnumerateCount(ctx context.Context) (int64, error) {
	var n int64
	err := filepath.WalkDir(p.localRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path == p.localRoot && os.IsNotExist(err) {
				return filepath.SkipAll
			}
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if path == p.localRoot {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && d.Name() == treegen.ManifestName {
			return nil
		}
		n++
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Remove empties the root rather than deleting and recreating it. The root is
// the operator's directory — often a mountpoint, where rmdir fails with EBUSY
// after the contents are already gone, and always something whose mode and ACL
// are not ours to reset.
func (p *posixProvisioner) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(p.localRoot)
	if os.IsNotExist(err) {
		return os.MkdirAll(p.localRoot, 0755)
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	fmt.Fprintf(p.out, "Removing %d top-level entries from %s\n", len(entries), p.localRoot)
	lastProgress := p.now()
	for i, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.removeAll(filepath.Join(p.localRoot, e.Name())); err != nil {
			return err
		}
		now := p.now()
		if now.Sub(lastProgress) >= p.progressInterval {
			fmt.Fprintf(p.out, "  removed %d of %d top-level entries\n", i+1, len(entries))
			lastProgress = now
		}
	}
	return nil
}

type scratchConfig struct {
	// LocalRoot is empty when the operator gave only --scratch-server-path and no
	// consumer needs a local path. Never treat empty as an error unconditionally.
	LocalRoot, TrialRoot string
	Roster               treegen.Roster
	ScaleName            string
	Scale                treegen.Scale
	CopiesOverride       int
	Workers              int
	Seed                 int64
	SafetyPrincipal      string
	FilesPerSubtree      int
	TrialDuration        time.Duration
	MaxTrialFiles        int64
	Reuse, Force         bool
}

type preparedScratch struct {
	LocalRoot, TrialRoot string
	TrialFiles           int64
	Copies               int
	PathsPerCopy         float64
	CalibrationOpsPerSec float64
	AutoSized            bool
}

// prepareScratch returns the tree every trial will run against. It reaches the
// tree only through prov: no os or filepath call against the scratch root, and
// no transport name anywhere in it. Both would reintroduce the kernel-path
// assumption one layer below the interface that exists to remove it.
func prepareScratch(ctx context.Context, cfg scratchConfig, prov ScratchProvisioner,
	baseline baselineTrialFunc, out io.Writer) (preparedScratch, error) {

	if cfg.TrialRoot == "" {
		return preparedScratch{}, fmt.Errorf("no trial root given")
	}
	if prov.NeedsLocalMount() && cfg.LocalRoot == "" {
		return preparedScratch{}, fmt.Errorf("this scratch backend needs a local mount path; give --scratch")
	}
	// Checked for both paths: it is the only ceiling on how much work a reused
	// tree can charge every trial, and reuse has no calibration to fall back on.
	if cfg.MaxTrialFiles <= 0 {
		return preparedScratch{}, fmt.Errorf("--max-trial-files must be positive")
	}

	// There is deliberately no capability refusal here. Generation does need a
	// mount this build can stamp through, but that condition -- NeedsLocalMount
	// and no kernel transport -- is a strict superset of what execute() already
	// refused at startup, and prepareScratch runs only downstream of it. A gate
	// here could never fire, and the advice it would have to give ("generate
	// elsewhere, then sweep here with --reuse-scratch") is false: posixProvisioner
	// reads the tree through the mount too, so reuse is refused at startup for
	// the same reason generation is. See cmd/sweep/main.go, the NeedsLocalMount
	// check before resolveRoots.
	if cfg.Reuse || cfg.Force {
		return reuseScratch(ctx, cfg, prov, out)
	}
	return generateScratch(ctx, cfg, prov, baseline, out)
}

// reuseScratch adopts a tree this invocation did not create. It never removes
// or rewrites anything: a manifest is read as evidence about the tree, never as
// permission to replace it.
func reuseScratch(ctx context.Context, cfg scratchConfig, prov ScratchProvisioner,
	out io.Writer) (preparedScratch, error) {

	prepared := preparedScratch{LocalRoot: cfg.LocalRoot, TrialRoot: cfg.TrialRoot}

	m, found, err := prov.Inspect(ctx)
	if err != nil {
		if !cfg.Force {
			return preparedScratch{}, fmt.Errorf("reading %s: %w", treegen.ManifestName, err)
		}
		fmt.Fprintf(out, "warning: %s is unreadable (%v); counting entries instead\n", treegen.ManifestName, err)
		found = false
	}
	if !found && !cfg.Force {
		// --reuse-scratch defaults to true, so this is also the error a first-run
		// operator meets against an empty scratch directory, and the two cases want
		// opposite advice: an empty root wants --regenerate-scratch, which generates,
		// while a root holding someone else's tree wants --force, which adopts it
		// read-only. Only an entry count separates them, and it is taken through the
		// provisioner — the same seam everything else here uses — never with an os
		// call against the root.
		n, countErr := prov.EnumerateCount(ctx)
		switch {
		case countErr != nil:
			// No flag is suggested here. Both candidates -- --regenerate-scratch and
			// --force -- re-enter this same count on their way to deciding anything,
			// so either would fail again on the error just reported. The only advice
			// that can succeed is to make the directory readable, so that is the
			// advice given.
			return preparedScratch{}, fmt.Errorf("--reuse-scratch needs a %s under %s, and %s could not be read to tell an empty directory from an existing tree: %v; fix the directory before sweeping it",
				treegen.ManifestName, cfg.TrialRoot, cfg.TrialRoot, countErr)
		case n == 0:
			// Replace, not add: --reuse-scratch defaults to true but an operator who
			// typed it explicitly meets the both-explicit refusal if they merely add
			// --regenerate-scratch beside it.
			return preparedScratch{}, fmt.Errorf("%s is empty, so --reuse-scratch has nothing to measure; use --regenerate-scratch to generate a tree there, replacing --reuse-scratch rather than adding to it",
				cfg.TrialRoot)
		default:
			// --regenerate-scratch is deliberately not offered here: generateScratch
			// refuses a non-empty root with no matching manifest, so it would only
			// trade this error for another.
			return preparedScratch{}, fmt.Errorf("--reuse-scratch needs a %s under %s, which instead holds %d entries; use --force to sweep a tree permissionreset did not generate",
				treegen.ManifestName, cfg.TrialRoot, n)
		}
	}

	countEntries := !found
	if found {
		if m.Failures > 0 {
			fmt.Fprintf(out, "warning: existing tree records %d stamping failures\n", m.Failures)
		}
		if m.Shape == nil {
			fmt.Fprintf(out, "warning: existing tree records no shape; cannot verify it matches the requested scale\n")
		} else if mismatch := shapeMismatch(requestedShape(cfg), *m.Shape); mismatch != "" {
			if !cfg.Force {
				return preparedScratch{}, fmt.Errorf("existing scratch tree does not match the requested shape: %s", mismatch)
			}
			fmt.Fprintf(out, "warning: existing scratch tree does not match the requested shape: %s\n", mismatch)
		}
		if m.TotalPaths > 0 {
			prepared.TrialFiles = m.TotalPaths
			if m.Shape != nil {
				prepared.Copies = m.Shape.Copies
			}
		} else if !cfg.Force {
			return preparedScratch{}, fmt.Errorf("existing %s under %s records %d paths, so there is nothing to measure",
				treegen.ManifestName, cfg.TrialRoot, m.TotalPaths)
		} else {
			fmt.Fprintf(out, "warning: existing %s records no path count; counting entries instead\n", treegen.ManifestName)
			countEntries = true
		}
	}

	if countEntries {
		n, err := prov.EnumerateCount(ctx)
		if err != nil {
			return preparedScratch{}, fmt.Errorf("counting %s: %w", cfg.TrialRoot, err)
		}
		fmt.Fprintf(out, "warning: could not verify that %s was generated by permissionreset or that it matches the requested shape; using a counted %d entries\n",
			cfg.TrialRoot, n)
		prepared.TrialFiles = n
	}

	// Reuse cannot size the tree, so these bounds are the only thing standing
	// between the sweep and a tree that carries no signal or costs more than the
	// operator allowed. A duration floor is impossible here: nothing is measured
	// before the search starts.
	if prepared.TrialFiles <= 0 {
		return preparedScratch{}, fmt.Errorf("%s holds no countable entries", cfg.TrialRoot)
	}
	if prepared.TrialFiles > cfg.MaxTrialFiles {
		return preparedScratch{}, fmt.Errorf("existing tree at %s holds %d paths, over the --max-trial-files ceiling of %d",
			cfg.TrialRoot, prepared.TrialFiles, cfg.MaxTrialFiles)
	}
	// The compared fields cannot catch a leftover probe tree: shapeConfig builds
	// the probe from this run's own SeedFiles, MaxDepth, Seed and FilesPerSubtree,
	// so every compared field matches by construction and only Copies differs —
	// and Copies is deliberately not compared. That leftover is reachable by
	// accident, not just in theory: fourteen error returns sit between Probe and
	// Remove, several of them ordinary flag mistakes, and --reuse-scratch defaults
	// to silently adopting the manifest that the aborted run left behind. Copies is
	// still the only number that says how much tree this is, so say it out loud.
	// A warning, not a refusal: measuring against a smaller tree can be
	// deliberate, but it must not be accidental.
	//
	// The comparison is against probeCopies and nothing else. cfg.Scale.Copies is
	// not the right reference and cannot be made into one: shapeConfig overwrites
	// it with the calibrated count, so a correctly sized tree records what sizing
	// chose, never the nominal scale — and when --max-trial-files clamps, it
	// records the clamp the tool itself asked the operator for. Nor is Scale.Copies
	// even the operator's request once --copies is wired; CopiesOverride is.
	// Probe-sized is the harm, so probe-sized is the test.
	if prepared.Copies > 0 && prepared.Copies <= probeCopies {
		fmt.Fprintf(out, "warning: existing tree records only %d copies, no more than the %d-copy probe tree an aborted run leaves behind, so it is likely far too small to separate one setting from another\n",
			prepared.Copies, probeCopies)
	}
	fmt.Fprintf(out, "Reusing scratch tree at %s: %d paths\n", cfg.TrialRoot, prepared.TrialFiles)
	return prepared, nil
}

// requestedShape is the shape this invocation asked for, for comparison against
// what an existing tree records.
func requestedShape(cfg scratchConfig) treegen.ManifestShape {
	return treegen.ManifestShape{
		Copies:          cfg.Scale.Copies,
		SeedFiles:       cfg.Scale.SeedFiles,
		MaxDepth:        cfg.Scale.MaxDepth,
		Seed:            cfg.Seed,
		FilesPerSubtree: cfg.FilesPerSubtree,
	}
}

// shapeMismatch reports the disagreements between a requested shape and a
// recorded one. Every field that changes what is in the tree is compared.
//
// Copies is the deliberate exception, and it must stay excluded: on the reuse
// path the tree was built by an earlier invocation whose copy count came out of
// that run's calibration, so it will essentially never equal this run's nominal
// Scale.Copies. Comparing it would reject every legitimate reuse.
func shapeMismatch(want, got treegen.ManifestShape) string {
	var diffs []string
	if got.SeedFiles != want.SeedFiles {
		diffs = append(diffs, fmt.Sprintf("seed_files %d, requested %d", got.SeedFiles, want.SeedFiles))
	}
	if got.MaxDepth != want.MaxDepth {
		diffs = append(diffs, fmt.Sprintf("max_depth %d, requested %d", got.MaxDepth, want.MaxDepth))
	}
	if got.Seed != want.Seed {
		diffs = append(diffs, fmt.Sprintf("seed %d, requested %d", got.Seed, want.Seed))
	}
	if got.FilesPerSubtree != want.FilesPerSubtree {
		diffs = append(diffs, fmt.Sprintf("files_per_subtree %d, requested %d", got.FilesPerSubtree, want.FilesPerSubtree))
	}
	if len(diffs) == 0 {
		return ""
	}
	msg := diffs[0]
	for _, d := range diffs[1:] {
		msg += "; " + d
	}
	return msg
}

func generateScratch(ctx context.Context, cfg scratchConfig, prov ScratchProvisioner,
	baseline baselineTrialFunc, out io.Writer) (preparedScratch, error) {

	if cfg.TrialDuration < minTrialDuration {
		return preparedScratch{}, fmt.Errorf("--trial-duration %s is below the %s minimum",
			cfg.TrialDuration, minTrialDuration)
	}
	if cfg.Workers <= 0 {
		return preparedScratch{}, fmt.Errorf("--tree-workers must be positive")
	}
	if cfg.Scale.SeedFiles <= 0 || cfg.Scale.MaxDepth <= 0 {
		return preparedScratch{}, fmt.Errorf("scale %q has no seed files or no depth", cfg.ScaleName)
	}
	if baseline == nil {
		return preparedScratch{}, fmt.Errorf("no calibration trial available")
	}

	// A generating invocation is --regenerate-scratch. It may replace only a tree
	// whose manifest names this exact root; markerless contents or a copied marker
	// may cover unrelated data. This is a per-root proof, not a per-file proof: a
	// matching marker authorizes removing everything beside it under the scratch
	// root. The check stays behind the provisioner seam because LocalRoot is empty
	// whenever the backend needs no mount.
	if m, found, err := prov.Inspect(ctx); err != nil {
		return preparedScratch{}, fmt.Errorf("inspecting %s: %w", cfg.TrialRoot, err)
	} else if found {
		target := generationTarget(cfg)
		if m.GeneratedTarget != target {
			return preparedScratch{}, fmt.Errorf("refusing --regenerate-scratch for %s: its %s names target %q, not %q, so it does not prove this tree is safe to replace; use --force without --regenerate-scratch to adopt it read-only",
				cfg.TrialRoot, treegen.ManifestName, m.GeneratedTarget, target)
		}
		fmt.Fprintf(out, "Clearing existing generated tree at %s before regeneration\n", cfg.TrialRoot)
		if err := prov.Remove(ctx); err != nil {
			return preparedScratch{}, fmt.Errorf("clearing existing scratch tree: %w", err)
		}
	} else if n, err := prov.EnumerateCount(ctx); err != nil {
		return preparedScratch{}, fmt.Errorf("counting %s: %w", cfg.TrialRoot, err)
	} else if n > 0 {
		return preparedScratch{}, fmt.Errorf("refusing --regenerate-scratch for %s: it holds %d entries but no %s proves the tree is safe to replace; use --force without --regenerate-scratch to adopt it read-only",
			cfg.TrialRoot, n, treegen.ManifestName)
	}

	// The probe is transient and is torn down before the real tree is built, so
	// --max-trial-files bounds the trial tree only, not this.
	shape := shapeConfig(cfg, probeCopies)
	fmt.Fprintf(out, "Calibrating: building a %d-copy probe tree at %s\n", probeCopies, cfg.TrialRoot)
	if err := prov.Probe(ctx, shape); err != nil {
		return preparedScratch{}, fmt.Errorf("probe generation: %w", err)
	}
	probe, found, err := prov.Inspect(ctx)
	if err != nil {
		return preparedScratch{}, fmt.Errorf("reading probe %s: %w", treegen.ManifestName, err)
	}
	if !found {
		return preparedScratch{}, fmt.Errorf("probe generation wrote no %s under %s", treegen.ManifestName, cfg.TrialRoot)
	}
	if probe.Failures > 0 {
		return preparedScratch{}, fmt.Errorf("probe generation reported %d failures over %d paths",
			probe.Failures, probe.TotalPaths)
	}
	if probe.GeneratedTarget != shape.Target {
		return preparedScratch{}, fmt.Errorf("probe %s claims target %q, not %q",
			treegen.ManifestName, probe.GeneratedTarget, shape.Target)
	}
	if probe.TotalPaths <= 0 {
		return preparedScratch{}, fmt.Errorf("probe %s records %d paths", treegen.ManifestName, probe.TotalPaths)
	}

	rate, err := baseline(ctx, cfg.TrialRoot)
	if err != nil {
		return preparedScratch{}, fmt.Errorf("calibration trial: %w", err)
	}
	if rate <= 0 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return preparedScratch{}, fmt.Errorf("calibration measured %v paths/s", rate)
	}

	pathsPerCopy := float64(probe.TotalPaths) / float64(probeCopies)
	maxCopies := int(math.Floor(float64(cfg.MaxTrialFiles) / pathsPerCopy))
	fmt.Fprintf(out, "  %.0f paths/s over %.0f paths/copy\n", rate, pathsPerCopy)

	if maxCopies < 1 {
		return preparedScratch{}, fmt.Errorf("--max-trial-files %d cannot hold even one %.0f-path copy, so no trial can reach the %s minimum; raise --max-trial-files or use a smaller scale",
			cfg.MaxTrialFiles, pathsPerCopy, minTrialDuration)
	}

	copies := cfg.CopiesOverride
	if copies > 0 {
		if copies > maxCopies {
			return preparedScratch{}, fmt.Errorf("--copies %d needs %.0f paths, over the --max-trial-files ceiling of %d (%.0f paths/copy, at most %d copies)",
				copies, float64(copies)*pathsPerCopy, cfg.MaxTrialFiles, pathsPerCopy, maxCopies)
		}
		if est := trialEstimate(copies, pathsPerCopy, rate); est < minTrialDuration {
			return preparedScratch{}, fmt.Errorf("--copies %d gives an estimated %s trial, below the %s minimum; raise --copies or drop it to let sizing choose",
				copies, roundSeconds(est), minTrialDuration)
		}
	} else {
		copies = int(math.Ceil(rate * cfg.TrialDuration.Seconds() / pathsPerCopy))
		if copies < 1 {
			copies = 1
		}
		if copies > maxCopies {
			capped := trialEstimate(maxCopies, pathsPerCopy, rate)
			fmt.Fprintf(out, "--max-trial-files %d caps the tree at %d copies (sizing wanted %d): requested %s of work per trial, estimated %s\n",
				cfg.MaxTrialFiles, maxCopies, copies, roundSeconds(cfg.TrialDuration), roundSeconds(capped))
			copies = maxCopies
		}
		if est := trialEstimate(copies, pathsPerCopy, rate); est < minTrialDuration {
			return preparedScratch{}, fmt.Errorf("%d copies give an estimated %s trial, below the %s minimum; raise --max-trial-files or use a larger scale",
				copies, roundSeconds(est), minTrialDuration)
		}
	}

	// Only now, and only because the marker still names the root this call just
	// created, may the probe tree be destroyed.
	confirm, found, err := prov.Inspect(ctx)
	if err != nil {
		return preparedScratch{}, fmt.Errorf("re-reading probe %s: %w", treegen.ManifestName, err)
	}
	if !found || confirm.GeneratedTarget != shape.Target {
		return preparedScratch{}, fmt.Errorf("refusing to remove %s: its %s no longer proves this run generated it",
			cfg.TrialRoot, treegen.ManifestName)
	}
	if err := prov.Remove(ctx); err != nil {
		return preparedScratch{}, fmt.Errorf("removing probe tree: %w", err)
	}

	full := shapeConfig(cfg, copies)
	fmt.Fprintf(out, "Generating %d copies (~%.0f paths) at %s\n", copies, float64(copies)*pathsPerCopy, cfg.TrialRoot)
	if err := prov.Provision(ctx, full); err != nil {
		return preparedScratch{}, fmt.Errorf("scratch generation: %w", err)
	}
	final, found, err := prov.Inspect(ctx)
	if err != nil {
		return preparedScratch{}, fmt.Errorf("reading %s: %w", treegen.ManifestName, err)
	}
	if !found {
		return preparedScratch{}, fmt.Errorf("generation wrote no %s under %s", treegen.ManifestName, cfg.TrialRoot)
	}
	if final.Failures > 0 {
		return preparedScratch{}, fmt.Errorf("generation reported %d failures over %d paths", final.Failures, final.TotalPaths)
	}
	if final.Shape == nil || final.Shape.Copies != copies {
		return preparedScratch{}, fmt.Errorf("generated %s does not record %d copies: %+v", treegen.ManifestName, copies, final.Shape)
	}
	if final.TotalPaths <= 0 {
		return preparedScratch{}, fmt.Errorf("generated %s records %d paths", treegen.ManifestName, final.TotalPaths)
	}

	return preparedScratch{
		LocalRoot:            cfg.LocalRoot,
		TrialRoot:            cfg.TrialRoot,
		TrialFiles:           final.TotalPaths,
		Copies:               copies,
		PathsPerCopy:         pathsPerCopy,
		CalibrationOpsPerSec: rate,
		AutoSized:            cfg.CopiesOverride == 0,
	}, nil
}

// shapeConfig describes a generation request. Target is a plain string handed
// to the provisioner, which is free to ignore it; nothing here touches it.
func shapeConfig(cfg scratchConfig, copies int) treegen.Config {
	target := generationTarget(cfg)
	scale := cfg.Scale
	scale.Copies = copies
	return treegen.Config{
		Target:          target,
		Roster:          cfg.Roster,
		Scale:           scale,
		Workers:         cfg.Workers,
		Seed:            cfg.Seed,
		SafetyPrincipal: cfg.SafetyPrincipal,
		FilesPerSubtree: cfg.FilesPerSubtree,
	}
}

func generationTarget(cfg scratchConfig) string {
	if cfg.LocalRoot != "" {
		return cfg.LocalRoot
	}
	return cfg.TrialRoot
}

func growScratch(ctx context.Context, cfg scratchConfig, prov ScratchProvisioner,
	prepared preparedScratch, rate float64, out io.Writer) (preparedScratch, bool, error) {

	// AutoSized is set only after the probe records a positive paths-per-copy
	// value. Keep this as a backstop for direct callers, not as reachable command
	// validation.
	if prepared.PathsPerCopy <= 0 {
		return preparedScratch{}, false, fmt.Errorf("cannot grow %s without a positive paths-per-copy measurement", cfg.TrialRoot)
	}
	// Leave 10% headroom above whichever target is larger: the requested trial or
	// the hard floor. At the legal 10s minimum, rebuilding to exactly 10s made the
	// result a coin flip against the measured 3.3% run-to-run noise.
	targetDuration := max(cfg.TrialDuration, minTrialDuration)
	growthDuration := time.Duration(math.Ceil(float64(targetDuration) * 1.10))
	copies := int(math.Ceil(rate * growthDuration.Seconds() / prepared.PathsPerCopy))
	if copies < 1 {
		copies = 1
	}
	maxCopies := int(math.Floor(float64(cfg.MaxTrialFiles) / prepared.PathsPerCopy))
	if maxCopies < 1 {
		return preparedScratch{}, false, fmt.Errorf("--max-trial-files %d cannot hold even one %.0f-path copy",
			cfg.MaxTrialFiles, prepared.PathsPerCopy)
	}
	if copies > maxCopies {
		wanted := copies
		copies = maxCopies
		if copies <= prepared.Copies {
			fmt.Fprintf(out, "--max-trial-files %d ceiling prevents growth beyond the existing %d copies (measured sizing wanted %d); the ceiling cannot satisfy the %s trial target\n",
				cfg.MaxTrialFiles, prepared.Copies, wanted, roundSeconds(cfg.TrialDuration))
			return prepared, false, nil
		}
		fmt.Fprintf(out, "--max-trial-files %d caps growth at %d copies (measured sizing wanted %d)\n",
			cfg.MaxTrialFiles, copies, wanted)
	}

	// The manifest came from this invocation's first full generation. Re-read it
	// immediately before removal so a replaced marker cannot authorize deleting a
	// tree the sweeper no longer owns.
	confirm, found, err := prov.Inspect(ctx)
	target := generationTarget(cfg)
	if err != nil {
		return preparedScratch{}, false, fmt.Errorf("re-reading generated %s before growth: %w", treegen.ManifestName, err)
	}
	if !found || confirm.GeneratedTarget != target {
		return preparedScratch{}, false, fmt.Errorf("refusing to grow %s: its %s no longer proves this run generated it",
			cfg.TrialRoot, treegen.ManifestName)
	}
	fmt.Fprintf(out, "Growing the trial tree from %d to %d copies after the measured baseline showed the calibrated tree was too small; rebuilding can take many minutes\n",
		prepared.Copies, copies)
	if err := prov.Remove(ctx); err != nil {
		return preparedScratch{}, false, fmt.Errorf("removing undersized scratch tree: %w", err)
	}

	shape := shapeConfig(cfg, copies)
	if err := prov.Provision(ctx, shape); err != nil {
		return preparedScratch{}, false, fmt.Errorf("scratch growth generation: %w", err)
	}
	final, found, err := prov.Inspect(ctx)
	if err != nil {
		return preparedScratch{}, false, fmt.Errorf("reading grown %s: %w", treegen.ManifestName, err)
	}
	if !found {
		return preparedScratch{}, false, fmt.Errorf("growth generation wrote no %s under %s", treegen.ManifestName, cfg.TrialRoot)
	}
	if final.Failures > 0 {
		return preparedScratch{}, false, fmt.Errorf("growth generation reported %d failures over %d paths", final.Failures, final.TotalPaths)
	}
	if final.Shape == nil || final.Shape.Copies != copies {
		return preparedScratch{}, false, fmt.Errorf("grown %s does not record %d copies: %+v", treegen.ManifestName, copies, final.Shape)
	}
	if final.TotalPaths <= 0 {
		return preparedScratch{}, false, fmt.Errorf("grown %s records %d paths", treegen.ManifestName, final.TotalPaths)
	}
	prepared.TrialFiles = final.TotalPaths
	prepared.Copies = copies
	return prepared, true, nil
}

func trialEstimate(copies int, pathsPerCopy, rate float64) time.Duration {
	return time.Duration(float64(copies) * pathsPerCopy / rate * float64(time.Second))
}

func roundSeconds(d time.Duration) time.Duration { return d.Round(time.Second) }
