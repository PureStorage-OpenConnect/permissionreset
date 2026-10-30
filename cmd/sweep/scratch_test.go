package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
)

// The fixture's seed and files-per-subtree are constants so manifestFor can
// record the same values the fixture requests. Every shape field a real
// manifest carries is populated: a double that leaves fields zero makes the
// comparison of those fields look untestable when it is not.
const (
	fixtureSeed            = 42
	fixtureFilesPerSubtree = 4
)

// scratchFixture deliberately names a root that does not exist. prepareScratch
// reaches the tree only through the provisioner, so no test needs the path to
// be real — and if prepareScratch ever grows an os.Stat or an os.ReadDir on it,
// every test here breaks, which is the point.
func scratchFixture(t *testing.T) scratchConfig {
	t.Helper()
	const root = "/nonexistent-sweep-scratch/tree"
	return scratchConfig{
		LocalRoot:       root,
		TrialRoot:       root,
		Roster:          treegen.Roster{Domain: "example.test", Roles: map[string]string{"owner": "alice"}},
		ScaleName:       "medium",
		Scale:           treegen.Scale{Copies: 50, SeedFiles: 100, MaxDepth: 10},
		Workers:         8,
		Seed:            fixtureSeed,
		SafetyPrincipal: "sweeper@example.test",
		FilesPerSubtree: fixtureFilesPerSubtree,
		TrialDuration:   30 * time.Second,
		MaxTrialFiles:   2_000_000,
	}
}

func manifestFor(scale treegen.Scale, total int64) treegen.Manifest {
	return treegen.Manifest{
		Version: treegen.ManifestVersion,
		Shape: &treegen.ManifestShape{
			Copies:          scale.Copies,
			SeedFiles:       scale.SeedFiles,
			MaxDepth:        scale.MaxDepth,
			Seed:            fixtureSeed,
			FilesPerSubtree: fixtureFilesPerSubtree,
		},
		TotalPaths: total,
		Applied:    total,
	}
}

// fakeProvisioner is the test double for the generation seam. It touches no
// filesystem: every answer comes from an in-memory manifest.
type fakeProvisioner struct {
	t              *testing.T
	pathsPerCopy   int64
	generated      []int
	existing       treegen.Manifest
	current        *treegen.Manifest
	enumerated     int64
	enumerateErr   error
	removes        int
	inspects       int
	noLocalMount   bool
	failOnGenerate bool
	// foreignTarget makes Inspect report a different GeneratedTarget once this
	// many inspections have happened — the marker changing under the sweeper
	// between calibration and teardown.
	foreignTarget int
	// genFailures is stamped into every generated manifest.
	genFailures int64
	// lieAboutCopies makes the full generation record a copy count it did not
	// build, so the caller cannot trust the shape it asked for.
	lieAboutCopies bool
	// extraPaths is added to the full tree's recorded path count, standing in
	// for the department and project directories a real fan-out also creates.
	extraPaths int64
	// cancelOnGenerate cancels from the named Probe/Provision call after the
	// in-memory manifest has been written, matching treegen's success-over-partial
	// cancellation shape.
	cancelOnGenerate int
	cancelOnRemove   int
	cancel           func()
}

func (f *fakeProvisioner) Probe(ctx context.Context, shape treegen.Config) error {
	return f.generate(shape)
}

func (f *fakeProvisioner) Provision(ctx context.Context, shape treegen.Config) error {
	return f.generate(shape)
}

func (f *fakeProvisioner) generate(shape treegen.Config) error {
	f.t.Helper()
	f.generated = append(f.generated, shape.Scale.Copies)
	// A provisioner with no target has nothing to identify the tree it built,
	// which is what both GeneratedTarget proofs rest on.
	if shape.Target == "" {
		f.t.Errorf("generation requested with no target")
	}
	if f.failOnGenerate {
		f.t.Errorf("unexpected generation of %d copies", shape.Scale.Copies)
		return errors.New("generation is not permitted in this test")
	}
	m := manifestFor(shape.Scale, int64(shape.Scale.Copies)*f.pathsPerCopy)
	m.GeneratedTarget = shape.Target
	m.Shape.Seed = shape.Seed
	m.Shape.FilesPerSubtree = shape.FilesPerSubtree
	m.Failures = f.genFailures
	if len(f.generated) > 1 {
		m.TotalPaths += f.extraPaths
		if f.lieAboutCopies {
			m.Shape.Copies = shape.Scale.Copies + 1
		}
	}
	f.current = &m
	if f.cancelOnGenerate == len(f.generated) && f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *fakeProvisioner) Inspect(ctx context.Context) (treegen.Manifest, bool, error) {
	f.inspects++
	if f.existing.TotalPaths > 0 || f.existing.Shape != nil {
		return f.existing, true, nil
	}
	if f.current != nil {
		m := *f.current
		if f.foreignTarget > 0 && f.inspects > f.foreignTarget {
			m.GeneratedTarget = "/some/other/tree"
		}
		return m, true, nil
	}
	return treegen.Manifest{}, false, nil
}

func (f *fakeProvisioner) EnumerateCount(ctx context.Context) (int64, error) {
	if f.enumerateErr != nil {
		return 0, f.enumerateErr
	}
	return f.enumerated, nil
}

func (f *fakeProvisioner) Remove(ctx context.Context) error {
	f.removes++
	if f.cancelOnRemove == f.removes && f.cancel != nil {
		f.cancel()
		return ctx.Err()
	}
	f.existing = treegen.Manifest{}
	f.current = nil
	return nil
}

func (f *fakeProvisioner) NeedsLocalMount() bool { return !f.noLocalMount }

func (f *fakeProvisioner) lastCopies() int {
	if len(f.generated) == 0 {
		return -1
	}
	return f.generated[len(f.generated)-1]
}

func constantRate(rate int64) baselineTrialFunc {
	return func(context.Context, string) (float64, error) { return float64(rate), nil }
}

func runFakePreparation(t *testing.T, cfg scratchConfig, pathsPerCopy, rate int64) ([]int, string) {
	t.Helper()
	prov := &fakeProvisioner{t: t, pathsPerCopy: pathsPerCopy}
	var buf bytes.Buffer
	if _, err := prepareScratch(context.Background(), cfg, prov, constantRate(rate), &buf); err != nil {
		t.Fatalf("prepareScratch: %v", err)
	}
	return prov.generated, buf.String()
}

func runFakePreparationError(t *testing.T, cfg scratchConfig, pathsPerCopy, rate int64) ([]int, error) {
	t.Helper()
	prov := &fakeProvisioner{t: t, pathsPerCopy: pathsPerCopy}
	_, err := prepareScratch(context.Background(), cfg, prov, constantRate(rate), io.Discard)
	return prov.generated, err
}

func cmpInts(got, want []int) string {
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Sprintf("generated copy counts = %v, want %v", got, want)
	}
	return ""
}

func TestPrepareScratchMeasuresFourCopiesBeforeGeneratingTheFullTree(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	baseline := func(_ context.Context, root string) (float64, error) {
		if got := prov.lastCopies(); got != 4 {
			t.Fatalf("probe copies = %d, want 4", got)
		}
		return 1000, nil
	}
	got, err := prepareScratch(context.Background(), scratchFixture(t), prov, baseline, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmpInts(prov.generated, []int{4, 30}); diff != "" {
		t.Fatal(diff)
	}
	if got.Copies != 30 || got.TrialFiles != 30000 {
		t.Fatalf("prepared = %+v", got)
	}
}

// Trials measure the whole root the operator will repair, never a child of it.
func TestPrepareScratchCalibratesAgainstExactlyTheTrialRoot(t *testing.T) {
	cfg := scratchFixture(t)
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	var seen []string
	baseline := func(_ context.Context, root string) (float64, error) {
		seen = append(seen, root)
		return 1000, nil
	}
	got, err := prepareScratch(context.Background(), cfg, prov, baseline, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != cfg.TrialRoot {
		t.Fatalf("calibration roots = %q, want exactly [%q]", seen, cfg.TrialRoot)
	}
	if got.TrialRoot != cfg.TrialRoot {
		t.Fatalf("TrialRoot = %q, want %q", got.TrialRoot, cfg.TrialRoot)
	}
}

// The sizing estimate is not the answer: what the search budgets against is the
// count the generated tree actually reports.
func TestPrepareScratchReturnsTheGeneratedPathCountNotTheEstimate(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, extraPaths: 7}
	got, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrialFiles != 30_007 {
		t.Fatalf("TrialFiles = %d, want the manifest's 30007", got.TrialFiles)
	}
}

// The mountless backend must reach full generation, not just reuse: both
// GeneratedTarget proofs fall back to TrialRoot when there is no local path.
func TestPrepareScratchGeneratesWithNoLocalRoot(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.LocalRoot = ""
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, noLocalMount: true}
	got, err := prepareScratch(context.Background(), cfg, prov, constantRate(1000), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmpInts(prov.generated, []int{4, 30}); diff != "" {
		t.Fatal(diff)
	}
	if got.TrialFiles != 30_000 || got.LocalRoot != "" || got.TrialRoot != cfg.TrialRoot {
		t.Fatalf("prepared = %+v", got)
	}
	if prov.removes != 1 {
		t.Fatalf("probe removals = %d, want 1", prov.removes)
	}
}

func TestPrepareScratchRejectsUnusableInputs(t *testing.T) {
	cases := []struct {
		name string
		want string
		edit func(*scratchConfig)
	}{
		{"no trial root", "no trial root", func(c *scratchConfig) { c.TrialRoot = "" }},
		// scratchConfig.Workers is fed from --tree-workers in main.go, not from any
		// flag named --workers; the sweeper has no such flag.
		{"no workers", "--tree-workers", func(c *scratchConfig) { c.Workers = 0 }},
		{"no seed files", "no seed files", func(c *scratchConfig) { c.Scale.SeedFiles = 0 }},
		{"no depth", "no depth", func(c *scratchConfig) { c.Scale.MaxDepth = 0 }},
		{"no file ceiling", "--max-trial-files", func(c *scratchConfig) { c.MaxTrialFiles = 0 }},
		{"trial too short", "10s minimum", func(c *scratchConfig) { c.TrialDuration = time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scratchFixture(t)
			tc.edit(&cfg)
			prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, failOnGenerate: true}
			_, err := prepareScratch(context.Background(), cfg, prov, constantRate(1000), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestPrepareScratchRemovesTheProbeTreeBeforeFullGeneration(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	if _, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard); err != nil {
		t.Fatal(err)
	}
	if prov.removes != 1 {
		t.Fatalf("probe removals = %d, want exactly 1", prov.removes)
	}
}

func TestRegenerateScratchClearsAProvenGeneratedTreeBeforeGenerating(t *testing.T) {
	cfg := scratchFixture(t)
	existing := manifestFor(cfg.Scale, 12_345)
	existing.GeneratedTarget = cfg.LocalRoot
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, existing: existing}

	got, err := prepareScratch(context.Background(), cfg, prov, constantRate(1000), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if prov.removes != 2 {
		t.Fatalf("removals = %d, want existing-tree and probe removals", prov.removes)
	}
	if diff := cmpInts(prov.generated, []int{4, 30}); diff != "" {
		t.Fatal(diff)
	}
	if got.Copies != 30 || got.TrialFiles != 30_000 {
		t.Fatalf("prepared = %+v", got)
	}
}

func TestRegenerateScratchRefusesANonEmptyRootWithoutAManifest(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, enumerated: 5, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no "+treegen.ManifestName) {
		t.Fatalf("error = %v, want a missing-manifest refusal", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want the read-only --force remedy", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0", prov.removes)
	}
	if len(prov.generated) != 0 {
		t.Fatalf("generated = %v, want no generation", prov.generated)
	}
}

func TestRegenerateScratchRefusesAManifestNamingAnotherRoot(t *testing.T) {
	cfg := scratchFixture(t)
	existing := manifestFor(cfg.Scale, 12_345)
	existing.GeneratedTarget = "/some/other/tree"
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, existing: existing, failOnGenerate: true}

	_, err := prepareScratch(context.Background(), cfg, prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "/some/other/tree") || !strings.Contains(err.Error(), cfg.LocalRoot) {
		t.Fatalf("error = %v, want both the foreign and requested roots", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want the read-only --force remedy", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0 for a foreign manifest", prov.removes)
	}
	if len(prov.generated) != 0 {
		t.Fatalf("generated = %v, want no generation", prov.generated)
	}
}

func TestGrowScratchRefusesAReplacedManifestBeforeRemoval(t *testing.T) {
	cfg := scratchFixture(t)
	existing := manifestFor(cfg.Scale, 30_000)
	existing.GeneratedTarget = "/some/other/tree"
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, existing: existing}
	prepared := preparedScratch{
		LocalRoot: cfg.LocalRoot, TrialRoot: cfg.TrialRoot,
		TrialFiles: 30_000, Copies: 30, PathsPerCopy: 1000, AutoSized: true,
	}

	_, _, err := growScratch(context.Background(), cfg, prov, prepared, 6000, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no longer proves") {
		t.Fatalf("error = %v, want the replaced-manifest refusal", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0 for a replaced manifest", prov.removes)
	}
	if len(prov.generated) != 0 {
		t.Fatalf("generated = %v, want no generation", prov.generated)
	}
}

func TestRegenerateScratchGeneratesIntoAnEmptyRootWithoutRemoving(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	got, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if prov.removes != 1 {
		t.Fatalf("removals = %d, want the probe removal only", prov.removes)
	}
	if diff := cmpInts(prov.generated, []int{4, 30}); diff != "" {
		t.Fatal(diff)
	}
	if got.Copies != 30 || got.TrialFiles != 30_000 {
		t.Fatalf("prepared = %+v", got)
	}
}

func TestGrowScratchAddsMarginAtTheMinimumDuration(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.TrialDuration = minTrialDuration
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	current := manifestFor(treegen.Scale{Copies: 5, SeedFiles: cfg.Scale.SeedFiles, MaxDepth: cfg.Scale.MaxDepth}, 5000)
	current.GeneratedTarget = cfg.LocalRoot
	prov.current = &current
	prepared := preparedScratch{
		LocalRoot: cfg.LocalRoot, TrialRoot: cfg.TrialRoot, TrialFiles: 5000,
		Copies: 5, PathsPerCopy: 1000, AutoSized: true,
	}
	got, grew, err := growScratch(context.Background(), cfg, prov, prepared, 1000, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !grew || got.Copies != 11 {
		t.Fatalf("grew=%v copies=%d, want 11 copies (10s floor plus 10%%)", grew, got.Copies)
	}
}

func TestPrepareScratchRejectsATrialDurationBelowTheFloor(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.TrialDuration = 5 * time.Second
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "10s minimum") {
		t.Fatalf("error = %v, want 10s minimum", err)
	}
}

func TestPrepareScratchCapsAutomaticCopiesAndAnnouncesShorterTrial(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.MaxTrialFiles = 2_000_000
	generated, output := runFakePreparation(t, cfg, 1_000_000, 100_000)
	if got := generated[len(generated)-1]; got != 2 {
		t.Fatalf("full copies = %d, want capped 2", got)
	}
	if !strings.Contains(output, "requested 30s") || !strings.Contains(output, "estimated 20s") {
		t.Fatalf("cap warning = %q", output)
	}
}

func TestPrepareScratchRejectsACapBelowTenSeconds(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.MaxTrialFiles = 500_000
	_, err := runFakePreparationError(t, cfg, 1_000_000, 100_000)
	if err == nil || !strings.Contains(err.Error(), "10s minimum") {
		t.Fatalf("error = %v, want 10s minimum", err)
	}
}

// The one-copy ceiling is refused by name, not just by the duration floor that
// would also catch it — the operator needs to know the scale cannot fit at all.
func TestPrepareScratchRejectsATreeWhereOneCopyExceedsTheCap(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.MaxTrialFiles = 500_000
	_, err := runFakePreparationError(t, cfg, 1_000_000, 100_000)
	if err == nil || !strings.Contains(err.Error(), "even one") || !strings.Contains(err.Error(), "10s minimum") {
		t.Fatalf("error = %v, want a one-copy-over-cap refusal", err)
	}
}

// maxCopies >= 1 here, so only the post-clamp duration check can catch this.
func TestPrepareScratchRejectsAClampedTrialShorterThanTheFloor(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.MaxTrialFiles = 1_500_000
	_, err := runFakePreparationError(t, cfg, 1_000_000, 200_000)
	if err == nil || !strings.Contains(err.Error(), "10s minimum") {
		t.Fatalf("error = %v, want 10s minimum after clamping", err)
	}
}

func TestPrepareScratchRejectsAGeneratedShapeItDidNotAskFor(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, lieAboutCopies: true}
	_, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "does not record 30 copies") {
		t.Fatalf("error = %v, want rejection of a mismatched generated shape", err)
	}
}

func TestPrepareScratchRejectsAProbeWithStampingFailures(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, genFailures: 3}
	_, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "3 failures") {
		t.Fatalf("error = %v, want refusal to size from a failed probe", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0", prov.removes)
	}
}

func TestPrepareScratchRejectsAProbeManifestForAnotherTarget(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, foreignTarget: 1}
	_, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "/some/other/tree") {
		t.Fatalf("error = %v, want rejection of a foreign probe marker", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0", prov.removes)
	}
}

// If the marker stops naming this run's root between calibration and teardown,
// the tree is no longer provably ours and must not be removed.
func TestPrepareScratchRefusesToRemoveATreeItCannotClaim(t *testing.T) {
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000, foreignTarget: 2}
	_, err := prepareScratch(context.Background(), scratchFixture(t), prov, constantRate(1000), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing to remove") {
		t.Fatalf("error = %v, want a refusal to remove", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0", prov.removes)
	}
	if diff := cmpInts(prov.generated, []int{4}); diff != "" {
		t.Fatal(diff)
	}
}

func TestPrepareScratchExplicitCopiesMustRespectFloorAndCeiling(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.CopiesOverride = 3
	cfg.MaxTrialFiles = 2_000
	_, err := runFakePreparationError(t, cfg, 1_000, 1_000)
	if err == nil || !strings.Contains(err.Error(), "--max-trial-files") {
		t.Fatalf("error = %v, want explicit-copy ceiling refusal", err)
	}
}

func TestPrepareScratchExplicitCopiesTooShortIsRefused(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.CopiesOverride = 3
	_, err := runFakePreparationError(t, cfg, 1_000, 1_000)
	if err == nil || !strings.Contains(err.Error(), "10s minimum") {
		t.Fatalf("error = %v, want 10s minimum for explicit copies", err)
	}
}

func TestReuseScratchSkipsGenerationAndCalibration(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, existing: manifestFor(cfg.Scale, 12_345), failOnGenerate: true}
	got, err := prepareScratch(context.Background(), cfg, prov,
		func(context.Context, string) (float64, error) {
			t.Fatal("calibration called in reuse mode")
			return 0, nil
		},
		io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrialFiles != 12_345 {
		t.Fatalf("TrialFiles = %d", got.TrialFiles)
	}
}

func TestReuseScratchRejectsShapeMismatch(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	mismatched := treegen.Scale{Copies: 8, SeedFiles: cfg.Scale.SeedFiles + 1, MaxDepth: cfg.Scale.MaxDepth}
	prov := &fakeProvisioner{t: t, existing: manifestFor(mismatched, 12_345), failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "seed_files") {
		t.Fatalf("error = %v, want shape mismatch", err)
	}
}

// Every shape field that changes what is in the tree is compared. Copies is
// excluded by design — see shapeMismatch — so it is asserted not to matter.
func TestReuseScratchComparesEveryContentShapeField(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		mutate func(*treegen.ManifestShape)
	}{
		{"seed files", "seed_files", func(s *treegen.ManifestShape) { s.SeedFiles++ }},
		{"max depth", "max_depth", func(s *treegen.ManifestShape) { s.MaxDepth++ }},
		{"seed", "seed", func(s *treegen.ManifestShape) { s.Seed = 999 }},
		{"files per subtree", "files_per_subtree", func(s *treegen.ManifestShape) { s.FilesPerSubtree = 64 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scratchFixture(t)
			cfg.Reuse = true
			existing := manifestFor(cfg.Scale, 12_345)
			tc.mutate(existing.Shape)
			prov := &fakeProvisioner{t: t, existing: existing, failOnGenerate: true}
			_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want mention of %q", err, tc.want)
			}
		})
	}

	// A different copy count is not a different shape: on the reuse path it came
	// from an earlier run's calibration and will never match the nominal scale.
	cfg := scratchFixture(t)
	cfg.Reuse = true
	existing := manifestFor(cfg.Scale, 12_345)
	existing.Shape.Copies = cfg.Scale.Copies + 1
	prov := &fakeProvisioner{t: t, existing: existing, failOnGenerate: true}
	if _, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard); err != nil {
		t.Fatalf("a differing copy count was rejected: %v", err)
	}
}

// Reuse cannot size the tree, so the recorded count is all there is to check:
// an arbitrarily small tree yields sub-millisecond trials that rank as signal,
// and an arbitrarily large one blows the operator's stated ceiling.
func TestReuseScratchBoundsTheAdoptedTreeSize(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	cfg.MaxTrialFiles = 10_000

	empty := &fakeProvisioner{t: t, existing: manifestFor(cfg.Scale, 0), failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, empty, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "nothing to measure") {
		t.Fatalf("empty-tree error = %v, want a refusal", err)
	}

	huge := &fakeProvisioner{t: t, existing: manifestFor(cfg.Scale, 10_001), failOnGenerate: true}
	_, err = prepareScratch(context.Background(), cfg, huge, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--max-trial-files") {
		t.Fatalf("oversized-tree error = %v, want a refusal", err)
	}

	fits := &fakeProvisioner{t: t, existing: manifestFor(cfg.Scale, 10_000), failOnGenerate: true}
	var buf bytes.Buffer
	got, err := prepareScratch(context.Background(), cfg, fits, nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrialFiles != 10_000 {
		t.Fatalf("TrialFiles = %d", got.TrialFiles)
	}
	if !strings.Contains(buf.String(), "10000 paths") {
		t.Fatalf("output = %q, want the tree size printed", buf.String())
	}
}

// A leftover probe tree passes every compared shape field by construction, so
// the copy count is the only thing left that says how much tree this is. The
// silent cases matter as much as the loud one: a warning that fires on a
// correctly sized tree costs the warnings that matter.
//
// The reference is probeCopies, never the nominal scale. shapeConfig overwrites
// Copies with the calibrated count, so a recorded count is what sizing chose —
// or what --max-trial-files clamped it to — and comparing it against
// cfg.Scale.Copies would warn at every legitimate reuse of the sweeper's own
// tree. The scale-varying cases below exist to hold that line.
func TestReuseWarnsWhenTheAdoptedTreeIsProbeSized(t *testing.T) {
	cases := []struct {
		name   string
		scale  treegen.Scale
		copies int
		total  int64
		warn   bool
	}{
		{"leftover probe tree", treegen.Scales["medium"], probeCopies, 200, true},
		{"one copy over the probe", treegen.Scales["medium"], probeCopies + 1, 250, false},
		{"a single-copy remnant", treegen.Scales["medium"], 1, 50, true},
		// Would have been silent before this round: 4*4 >= 10, so the old ratio
		// never fired on a probe tree at the smallest scale.
		{"probe tree at small scale", treegen.Scales["small"], probeCopies, 200, true},
		// Would have warned before this round: an ordinary 2,000 paths/s
		// calibration picks ~240 copies against a nominal 5000, and 240*4 < 5000.
		{"xlarge calibrated well below nominal", treegen.Scales["xlarge"], 240, 240_000, false},
		// The --max-trial-files clamp records the ceiling the tool itself asked
		// the operator for; warning at that is warning at correct behavior.
		{"clamped to the stated ceiling", treegen.Scales["xlarge"], 100, 100_000, false},
		{"calibration landed above nominal", treegen.Scales["medium"], 61, 61_000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scratchFixture(t)
			cfg.Reuse = true
			cfg.Scale = tc.scale
			existing := manifestFor(cfg.Scale, tc.total)
			existing.Shape.Copies = tc.copies
			prov := &fakeProvisioner{t: t, existing: existing, failOnGenerate: true}
			var buf bytes.Buffer
			if _, err := prepareScratch(context.Background(), cfg, prov, nil, &buf); err != nil {
				t.Fatal(err)
			}
			got := strings.Contains(buf.String(), "far too small")
			if got != tc.warn {
				t.Fatalf("warned = %v, want %v; output = %q", got, tc.warn, buf.String())
			}
			if tc.warn && !strings.Contains(buf.String(), fmt.Sprintf("only %d copies, no more than the %d-copy probe", tc.copies, probeCopies)) {
				t.Fatalf("output = %q, want the recorded and probe copy counts named", buf.String())
			}
		})
	}

	// A tree that records no shape has no copy count to judge, and must not be
	// warned about on the strength of a zero.
	cfg := scratchFixture(t)
	cfg.Reuse = true
	shapeless := manifestFor(cfg.Scale, 12_345)
	shapeless.Shape = nil
	var buf bytes.Buffer
	if _, err := prepareScratch(context.Background(), cfg, &fakeProvisioner{t: t, existing: shapeless, failOnGenerate: true}, nil, &buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "far too small") {
		t.Fatalf("output = %q, want no size warning for an unrecorded shape", buf.String())
	}
}

// The counted --force fallback is bounded at both ends too: an unverified tree
// is exactly the one whose size nobody has checked.
func TestForceBoundsACountedTree(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Force = true
	cfg.MaxTrialFiles = 100
	prov := &fakeProvisioner{t: t, enumerated: 101, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--max-trial-files") {
		t.Fatalf("error = %v, want the ceiling to bind on a counted tree", err)
	}

	cfg.MaxTrialFiles = 2_000_000
	emptyProv := &fakeProvisioner{t: t, enumerated: 0, failOnGenerate: true}
	_, err = prepareScratch(context.Background(), cfg, emptyProv, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no countable entries") {
		t.Fatalf("error = %v, want a refusal of an empty counted tree", err)
	}
}

func TestReuseScratchWithoutAMarkerIsFatal(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, enumerated: 999, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), treegen.ManifestName) {
		t.Fatalf("error = %v, want a missing-marker refusal", err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals = %d, want 0", prov.removes)
	}
}

// Every operator-facing flag name below is asserted here because nothing
// asserted them before, and all five had gone stale against the shipped flag
// set. The assertions match the flag token an operator would search for, not
// the sentence around it.

// The advice an empty scratch directory gets is the one with real consequence:
// --reuse-scratch defaults to true, so this is the first error a new operator
// meets, and --force would only authorize counting nothing.
func TestReuseWithoutAMarkerOnAnEmptyRootAsksForRegeneration(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, enumerated: 0, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil {
		t.Fatal("an empty root under --reuse-scratch must be an error")
	}
	if !strings.Contains(err.Error(), "--regenerate-scratch") {
		t.Fatalf("error = %v, want it to point at --regenerate-scratch", err)
	}
	if strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, must not offer --force: it counts an empty tree, it does not generate one", err)
	}
}

// A root that already holds a tree is the other case, and it wants --force.
func TestReuseWithoutAMarkerOnAPopulatedRootAsksForForce(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, enumerated: 999, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil {
		t.Fatal("a markerless populated root under --reuse-scratch must be an error")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want it to point at --force", err)
	}
	if !strings.Contains(err.Error(), "--reuse-scratch") {
		t.Fatalf("error = %v, want it to name --reuse-scratch", err)
	}
	// --regenerate-scratch would only trade this refusal for generateScratch's
	// non-empty-root refusal, so it must not be offered.
	if strings.Contains(err.Error(), "--regenerate-scratch") {
		t.Fatalf("error = %v, must not offer --regenerate-scratch for a non-empty root", err)
	}
}

// An uncountable root cannot be classified, and neither escape hatch can fix
// that: --regenerate-scratch and --force both re-enter the same count on their
// way to deciding anything, so either would fail again on the error just
// reported. The message therefore reports the count failure and stops, rather
// than offering a flag that cannot succeed.
func TestReuseWithoutAMarkerOffersNoFlagWhenTheRootCannotBeCounted(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, enumerateErr: errors.New("permission denied"), failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil {
		t.Fatal("an uncountable root under --reuse-scratch must be an error")
	}
	// The advice, not just the refusal. Offering no flag is only defensible
	// because the message says what will work instead; without that clause this
	// branch degrades into a dead end.
	for _, want := range []string{"--reuse-scratch", "permission denied", "fix the directory before sweeping it"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want mention of %q", err, want)
		}
	}
	for _, unwanted := range []string{"--regenerate-scratch", "--force"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Fatalf("error = %v, must not offer %s: it re-runs the count that just failed", err, unwanted)
		}
	}
}

// The empty-root advice must say to replace --reuse-scratch, not to add
// --regenerate-scratch beside it: an operator who typed --reuse-scratch
// explicitly and follows "add" meets the both-explicit refusal instead of a
// sweep.
func TestEmptyRootAdviceSaysToReplaceReuseScratch(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, enumerated: 0, failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil {
		t.Fatal("an empty root under --reuse-scratch must be an error")
	}
	if !strings.Contains(err.Error(), "replacing --reuse-scratch") {
		t.Fatalf("error = %v, want it to say --regenerate-scratch replaces --reuse-scratch", err)
	}
}

func TestForceImpliesReuseAndCountsWithoutGenerating(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Force = true
	prov := &fakeProvisioner{t: t, enumerated: 37, failOnGenerate: true}
	got, err := prepareScratch(context.Background(), cfg, prov,
		func(context.Context, string) (float64, error) {
			t.Fatal("calibration called under --force")
			return 0, nil
		},
		io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrialFiles != 37 {
		t.Fatalf("TrialFiles = %d, want enumerated count 37", got.TrialFiles)
	}
}

func TestForceNeverRemovesTheTree(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.Force = true
	mismatched := treegen.Scale{Copies: 8, SeedFiles: cfg.Scale.SeedFiles + 1, MaxDepth: cfg.Scale.MaxDepth}
	prov := &fakeProvisioner{t: t, existing: manifestFor(mismatched, 500), enumerated: 37, failOnGenerate: true}
	var buf bytes.Buffer
	got, err := prepareScratch(context.Background(), cfg, prov, nil, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if prov.removes != 0 {
		t.Fatalf("removals under --force = %d, want 0", prov.removes)
	}
	if got.TrialFiles != 500 {
		t.Fatalf("TrialFiles = %d, want the manifest count", got.TrialFiles)
	}
	if !strings.Contains(buf.String(), "seed_files") {
		t.Fatalf("force output = %q, want a shape-mismatch warning", buf.String())
	}
}

func TestPrepareScratchWorksWithNoLocalRoot(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.LocalRoot = ""
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, noLocalMount: true,
		existing: manifestFor(cfg.Scale, 12_345), failOnGenerate: true}
	got, err := prepareScratch(context.Background(), cfg, prov,
		func(context.Context, string) (float64, error) {
			t.Fatal("calibration called in reuse mode")
			return 0, nil
		},
		io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrialFiles != 12_345 {
		t.Fatalf("TrialFiles = %d", got.TrialFiles)
	}
}

func TestPrepareScratchRequiresALocalRootWhenTheProvisionerNeedsAMount(t *testing.T) {
	cfg := scratchFixture(t)
	cfg.LocalRoot = ""
	cfg.Reuse = true
	prov := &fakeProvisioner{t: t, existing: manifestFor(cfg.Scale, 12_345), failOnGenerate: true}
	_, err := prepareScratch(context.Background(), cfg, prov, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "local mount") {
		t.Fatalf("error = %v, want a local-mount requirement", err)
	}
	// The flag that supplies that path is --scratch. The negative assertion is
	// what does the work: "give --scratch-path" would still contain the positive
	// substring, so only rejecting the longer form catches a stale name.
	if !strings.Contains(err.Error(), "give --scratch") {
		t.Fatalf("error = %v, want it to name --scratch", err)
	}
	if strings.Contains(err.Error(), "--scratch-path") {
		t.Fatalf("error = %v, names --scratch-path, which is not a flag this command defines", err)
	}
}

// posixProvisioner is the kernel-mount backend, so its own tests use a real
// tmpdir — that is not a leak of the seam, it is the seam's one implementation.

func newPosixFixture(t *testing.T) (*posixProvisioner, string) {
	t.Helper()
	root := t.TempDir()
	return newPosixProvisioner(root, treegen.Config{
		Roster:  treegen.Roster{Domain: "example.test", Roles: map[string]string{"owner": "alice"}},
		Workers: 2,
	}), root
}

func TestPosixEnumerateCountSkipsSymlinksAndTheManifest(t *testing.T) {
	prov, root := newPosixFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "dept", "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dept", "proj", "f.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, treegen.ManifestName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	n, err := prov.EnumerateCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // dept, dept/proj, dept/proj/f.txt
		t.Fatalf("count = %d, want 3", n)
	}
}

func TestPosixEnumerateCountAbsentRootIsZero(t *testing.T) {
	prov := newPosixProvisioner(filepath.Join(t.TempDir(), "missing"), treegen.Config{})
	n, err := prov.EnumerateCount(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("count = %d, err = %v, want 0, nil", n, err)
	}
}

// An unreadable directory is not an empty one: a zero count is what authorizes
// generating into the root.
func TestPosixEnumerateCountReportsAnUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	prov, root := newPosixFixture(t)
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "inner"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0755) })
	if _, err := prov.EnumerateCount(context.Background()); err == nil {
		t.Fatal("an unreadable directory counted as empty")
	}
}

// Remove empties the root; it must not delete and recreate it, which would drop
// the operator's mode and fail with EBUSY on a mountpoint.
func TestPosixRemoveEmptiesTheRootInPlace(t *testing.T) {
	prov, root := newPosixFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "dept", "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, treegen.ManifestName), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	// A dotfile, because treegen writes one: a surviving .seed blocks
	// RunContext's own emptiness refusal outright, so an incomplete Remove does
	// not merely leave litter, it breaks the very next Provision.
	if err := os.WriteFile(filepath.Join(root, ".seed"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("root was replaced rather than emptied")
	}
	if after.Mode().Perm() != 0700 {
		t.Fatalf("root mode = %v, want 0700 preserved", after.Mode().Perm())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("root still holds %d entries", len(entries))
	}
}

func TestPosixRemoveStopsBetweenTopLevelEntriesWhenCanceled(t *testing.T) {
	prov, root := newPosixFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	prov.removeAll = func(path string) error {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		cancel()
		return nil
	}
	prov.out = io.Discard
	for _, name := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := prov.Remove(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries left = %d, want cancellation before the second top-level removal", len(entries))
	}
}

func TestPosixRemoveReportsProgress(t *testing.T) {
	prov, root := newPosixFixture(t)
	var out strings.Builder
	prov.out = &out
	tick := int64(0)
	prov.now = func() time.Time {
		tick++
		return time.Unix(tick, 0)
	}
	prov.progressInterval = time.Second
	for _, name := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := prov.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "removed 1 of 2 top-level entries") {
		t.Fatalf("output = %q, want periodic removal progress", out.String())
	}
}

func TestPosixInspectReportsAbsentAndPresentTrees(t *testing.T) {
	prov, root := newPosixFixture(t)
	if _, found, err := prov.Inspect(context.Background()); err != nil || found {
		t.Fatalf("found = %v, err = %v, want false, nil", found, err)
	}
	body := `{"version":1,"generated_target":"` + root + `","total_paths":12,"shape":{"copies":3}}`
	if err := os.WriteFile(filepath.Join(root, treegen.ManifestName), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	m, found, err := prov.Inspect(context.Background())
	if err != nil || !found || m.TotalPaths != 12 || m.Shape == nil || m.Shape.Copies != 3 {
		t.Fatalf("manifest = %+v, found = %v, err = %v", m, found, err)
	}
}

func TestPosixNeedsLocalMount(t *testing.T) {
	prov, _ := newPosixFixture(t)
	if !prov.NeedsLocalMount() {
		t.Fatal("the kernel-mount backend must require a local mount")
	}
}
