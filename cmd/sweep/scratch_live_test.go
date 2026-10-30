package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
)

// The tests in this file are the only ones in this package that touch a real
// filesystem, and they exist because every other test in it uses
// fakeProvisioner: the fake proves prepareScratch never reaches around the
// seam, and proves nothing whatsoever about the one implementation that does
// the reaching. posixProvisioner's whole surface — treegen.RunContext against
// a live export, ReadManifest, a WalkDir count, and an in-place Remove of a
// mountpoint — is untested until it runs on an NFS mount.
//
// They are skipped unless both of these are set, so an ordinary `go test ./...`
// is unaffected:
//
//	PERMISSIONRESET_LIVE_SCRATCH     absolute path to an empty scratch directory on
//	                            an NFSv4.1 mount; these tests create, stamp and
//	                            DELETE everything beneath it
//	PERMISSIONRESET_LIVE_PRINCIPALS  path to a treegen roster JSON whose principals
//	                            the target server resolves
//
// The scratch path must be one nobody else is using: liveRoot subdirectories
// are removed without further confirmation.
func liveConfig(t *testing.T) (root string, roster treegen.Roster) {
	t.Helper()
	root = os.Getenv("PERMISSIONRESET_LIVE_SCRATCH")
	rosterPath := os.Getenv("PERMISSIONRESET_LIVE_PRINCIPALS")
	if root == "" || rosterPath == "" {
		t.Skip("set PERMISSIONRESET_LIVE_SCRATCH and PERMISSIONRESET_LIVE_PRINCIPALS to run live scratch tests")
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("PERMISSIONRESET_LIVE_SCRATCH must be absolute: %q", root)
	}
	data, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	if err := json.Unmarshal(data, &roster); err != nil {
		t.Fatalf("parse roster: %v", err)
	}
	if roster.Domain == "" || len(roster.Roles) == 0 {
		t.Fatalf("roster %s has no domain or roles", rosterPath)
	}
	return root, roster
}

// liveProvisioner returns a provisioner over a fresh subdirectory of the live
// root, and registers its removal.
func liveProvisioner(t *testing.T, name string) (*posixProvisioner, treegen.Config) {
	t.Helper()
	root, roster := liveConfig(t)
	target := filepath.Join(root, name)
	if err := os.RemoveAll(target); err != nil {
		t.Fatalf("clear %s: %v", target, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(target); err != nil {
			t.Errorf("cleanup %s: %v", target, err)
		}
	})
	// SafetyPrincipal is left unset so treegen derives it from the running
	// account, which is the whole point of the safety ACE: the account that
	// generates the tree has to be able to come back and delete it. Naming a
	// roster role here instead stamps an ACL that locks the test runner out of
	// the directories it just created, and fan-out fails with EPERM for
	// everyone whose username is not that role.
	base := treegen.Config{
		Roster:          roster,
		Workers:         64,
		Seed:            7,
		FilesPerSubtree: 4,
	}
	return newPosixProvisioner(target, base), base
}

func liveShape(base treegen.Config, copies int) treegen.Config {
	shape := base
	shape.Scale = treegen.Scale{Copies: copies, SeedFiles: 50, MaxDepth: 6}
	return shape
}

// TestLivePosixProvisionerCycle walks the exact sequence generateScratch drives
// — Inspect on an absent root, Probe, Inspect, EnumerateCount, Remove, Inspect
// again, Provision — against a real export. Remove between the two generations
// is the step no fake can stand in for: it empties a directory in place rather
// than recreating it, because on an NFS mountpoint rmdir fails with EBUSY once
// the contents are gone.
func TestLivePosixProvisionerCycle(t *testing.T) {
	prov, base := liveProvisioner(t, "cycle")
	ctx := context.Background()

	if _, ok, err := prov.Inspect(ctx); err != nil || ok {
		t.Fatalf("Inspect on absent root = ok %v, err %v; want false, nil", ok, err)
	}
	if n, err := prov.EnumerateCount(ctx); err != nil || n != 0 {
		t.Fatalf("EnumerateCount on absent root = %d, %v; want 0, nil", n, err)
	}

	if err := prov.Probe(ctx, liveShape(base, probeCopies)); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	probe, ok, err := prov.Inspect(ctx)
	if err != nil || !ok {
		t.Fatalf("Inspect after Probe = ok %v, err %v", ok, err)
	}
	if probe.Shape == nil {
		t.Fatal("probe manifest records no shape")
	}
	if probe.Shape.Copies != probeCopies || probe.Shape.Seed != base.Seed {
		t.Fatalf("probe shape = %+v", *probe.Shape)
	}
	if probe.GeneratedTarget != prov.localRoot {
		t.Fatalf("GeneratedTarget = %q, want %q", probe.GeneratedTarget, prov.localRoot)
	}
	// TotalPaths counts distinct paths, Applied counts stamp operations, and
	// the two differ on purpose: an outlier file is stamped a second time with
	// a file scenario, so it contributes one path and two operations. Asserting
	// equality would pin a bug rather than the behaviour.
	if probe.Failures != 0 || probe.TotalPaths <= 0 {
		t.Fatalf("probe manifest = total %d applied %d failures %d",
			probe.TotalPaths, probe.Applied, probe.Failures)
	}
	if want := probe.TotalPaths + int64(len(probe.FileOutliers)); probe.Applied != want {
		t.Fatalf("probe manifest applied = %d, want %d (total %d + %d outliers)",
			probe.Applied, want, probe.TotalPaths, len(probe.FileOutliers))
	}

	// The walk and the manifest must agree exactly: both count distinct paths,
	// so any drift is a real accounting defect. prepareScratch divides
	// total_paths by probeCopies to get paths-per-copy, and an over-count
	// there shrinks every tree it sizes, which is why this is exact and not a
	// bound.
	counted, err := prov.EnumerateCount(ctx)
	if err != nil {
		t.Fatalf("EnumerateCount after Probe: %v", err)
	}
	if int64(counted) != probe.TotalPaths {
		t.Fatalf("EnumerateCount = %d, manifest total_paths = %d; want equal",
			counted, probe.TotalPaths)
	}

	if err := prov.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Remove empties in place: the root itself must survive, and Inspect must
	// report no tree.
	if fi, err := os.Stat(prov.localRoot); err != nil || !fi.IsDir() {
		t.Fatalf("root after Remove: stat err %v, dir %v", err, fi)
	}
	if _, ok, err := prov.Inspect(ctx); err != nil || ok {
		t.Fatalf("Inspect after Remove = ok %v, err %v; want false, nil", ok, err)
	}
	if n, err := prov.EnumerateCount(ctx); err != nil || n != 0 {
		t.Fatalf("EnumerateCount after Remove = %d, %v; want 0, nil", n, err)
	}

	const fullCopies = probeCopies * 3
	if err := prov.Provision(ctx, liveShape(base, fullCopies)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	full, ok, err := prov.Inspect(ctx)
	if err != nil || !ok {
		t.Fatalf("Inspect after Provision = ok %v, err %v", ok, err)
	}
	if full.Shape == nil || full.Shape.Copies != fullCopies {
		t.Fatalf("full shape = %+v, want %d copies", full.Shape, fullCopies)
	}
	if full.Failures != 0 {
		t.Fatalf("full manifest reports %d failures", full.Failures)
	}
	// Copies is the only shape field that changed, so the path count is the
	// only evidence that Provision built the larger tree and not the probe's.
	if full.TotalPaths <= probe.TotalPaths {
		t.Fatalf("full total %d not above probe total %d", full.TotalPaths, probe.TotalPaths)
	}
}

// TestLivePrepareScratchSizesFromARealProbe runs the whole sizing path against
// the real provisioner. The baseline callback returns a fixed rate so the
// arithmetic stays deterministic — what is under test is that a real probe
// tree's manifest feeds that arithmetic, and that the chosen full tree is then
// actually built.
func TestLivePrepareScratchSizesFromARealProbe(t *testing.T) {
	prov, base := liveProvisioner(t, "sized")
	shape := liveShape(base, 0)

	const rate = 2000.0
	cfg := scratchConfig{
		LocalRoot:       prov.localRoot,
		TrialRoot:       prov.localRoot,
		Roster:          base.Roster,
		ScaleName:       "small",
		Scale:           shape.Scale,
		Workers:         base.Workers,
		Seed:            base.Seed,
		SafetyPrincipal: base.SafetyPrincipal,
		FilesPerSubtree: base.FilesPerSubtree,
		TrialDuration:   10 * time.Second,
		MaxTrialFiles:   200_000,
	}
	cfg.Scale.Copies = 10

	var baselineRoot string
	baseline := func(_ context.Context, root string) (float64, error) {
		baselineRoot = root
		// The probe tree must exist and be readable at the moment the
		// calibration trial runs, not merely before or after it.
		if _, err := treegen.ReadManifest(root); err != nil {
			t.Errorf("manifest unreadable during calibration: %v", err)
		}
		return rate, nil
	}

	var out strings.Builder
	prepared, err := prepareScratch(context.Background(), cfg, prov, baseline, &out)
	if err != nil {
		t.Fatalf("prepareScratch: %v\noutput:\n%s", err, out.String())
	}
	if baselineRoot != prov.localRoot {
		t.Fatalf("calibration ran over %q, want the trial root %q", baselineRoot, prov.localRoot)
	}
	if prepared.CalibrationOpsPerSec != rate {
		t.Fatalf("CalibrationOpsPerSec = %v, want %v", prepared.CalibrationOpsPerSec, rate)
	}
	if prepared.Copies <= 0 || prepared.TrialFiles <= 0 {
		t.Fatalf("prepared = %+v", prepared)
	}

	// The returned count must be the tree that is on the server now.
	final, ok, err := prov.Inspect(context.Background())
	if err != nil || !ok {
		t.Fatalf("Inspect after prepareScratch = ok %v, err %v", ok, err)
	}
	if final.TotalPaths != prepared.TrialFiles {
		t.Fatalf("TrialFiles = %d but manifest records %d", prepared.TrialFiles, final.TotalPaths)
	}
	if final.Shape == nil || final.Shape.Copies != prepared.Copies {
		t.Fatalf("manifest shape %+v disagrees with prepared copies %d", final.Shape, prepared.Copies)
	}
	if final.Failures != 0 {
		t.Fatalf("final manifest reports %d failures", final.Failures)
	}
}

// TestLiveReuseAdoptsAGeneratedTree proves the reuse path accepts a tree the
// real provisioner built, and that it neither regenerates nor calibrates. The
// offline reuse tests assert this against a synthesized manifest; only a real
// one proves the fields treegen actually writes are the fields reuseScratch
// compares.
func TestLiveReuseAdoptsAGeneratedTree(t *testing.T) {
	prov, base := liveProvisioner(t, "reuse")
	ctx := context.Background()

	const copies = 6
	if err := prov.Provision(ctx, liveShape(base, copies)); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	generated, _, err := prov.Inspect(ctx)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	cfg := scratchConfig{
		LocalRoot:       prov.localRoot,
		TrialRoot:       prov.localRoot,
		Roster:          base.Roster,
		ScaleName:       "small",
		Scale:           treegen.Scale{Copies: copies, SeedFiles: 50, MaxDepth: 6},
		Workers:         base.Workers,
		Seed:            base.Seed,
		SafetyPrincipal: base.SafetyPrincipal,
		FilesPerSubtree: base.FilesPerSubtree,
		TrialDuration:   10 * time.Second,
		MaxTrialFiles:   200_000,
		Reuse:           true,
	}

	var out strings.Builder
	prepared, err := prepareScratch(ctx, cfg, prov, func(context.Context, string) (float64, error) {
		t.Error("calibration ran in reuse mode")
		return 0, nil
	}, &out)
	if err != nil {
		t.Fatalf("prepareScratch --reuse: %v\noutput:\n%s", err, out.String())
	}
	if prepared.TrialFiles != generated.TotalPaths {
		t.Fatalf("TrialFiles = %d, want the manifest's %d", prepared.TrialFiles, generated.TotalPaths)
	}
	if prepared.Copies != copies {
		t.Fatalf("Copies = %d, want %d", prepared.Copies, copies)
	}
	// A probe-sized tree is the case the warning exists for, and this tree is
	// larger than one, so the warning must be absent.
	if strings.Contains(out.String(), "likely far too small") {
		t.Fatalf("probe-size warning fired for a %d-copy tree:\n%s", copies, out.String())
	}
}
