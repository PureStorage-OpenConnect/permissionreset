package treegen

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// planSeedEntries must produce exactly what collectSeedPaths would return for a
// seed tree BuildSeedContext had just built from the same seed: same paths,
// same IsDir flags, same ORDER.
//
// This is the test that keeps the kernel and userspace transports from drifting
// apart. If the two disagree, a --seed no longer names one tree shape: a
// kernel-generated tree and a userspace-generated tree from the same seed are
// different trees, and every cross-transport benchmark silently compares
// unlike things. It runs offline -- BuildSeedContext writes into t.TempDir().
//
// The failure is reported in two stages on purpose. A set difference means the
// two paths genuinely describe different trees, which is the serious case. An
// order-only difference means they describe the same tree in a different
// sequence, which is far less serious but still worth holding: the entry list
// is replayed to create the tree, so its order decides whether a parent is
// created before its children.
func TestPlanSeedEntriesMatchesBuildSeedContext(t *testing.T) {
	cases := []struct {
		name             string
		nFiles, maxDepth int
	}{
		{"small", 100, 6},
		{"medium", 1000, 8},
		{"large", 5000, 10},
		{"depth-past-the-chain-cap", 500, 20},
		{"shallow", 50, 3},
		{"depth-at-the-branch-floor", 50, 2},
		{"tiny", 4, 5},
		{"no-files", 0, 6},
	}
	seeds := []int64{1, 42, 1337, 20260830}

	for _, tc := range cases {
		for _, seed := range seeds {
			t.Run(fmt.Sprintf("%s/seed=%d", tc.name, seed), func(t *testing.T) {
				dir := t.TempDir()
				if _, err := BuildSeedContext(t.Context(), dir, tc.nFiles, tc.maxDepth,
					rand.New(rand.NewSource(seed))); err != nil {
					t.Fatalf("BuildSeedContext: %v", err)
				}
				want, err := collectSeedPaths(dir)
				if err != nil {
					t.Fatalf("collectSeedPaths: %v", err)
				}

				got, _ := planSeedEntries(tc.nFiles, tc.maxDepth, rand.New(rand.NewSource(seed)))

				if diff := describeSetDiff(got, want); diff != "" {
					t.Fatalf("the planner and the on-disk seed describe DIFFERENT TREES.\n%s\n"+
						"  A --seed no longer names one tree shape: a kernel-generated tree and a\n"+
						"  userspace-generated tree from this seed are not the same tree.", diff)
				}

				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("same tree, different ORDER at entry %d: planned %+v, on-disk %+v\n"+
							"  planSeedEntries sorts with walkLess; collectSeedPaths uses\n"+
							"  filepath.Walk, which is pre-order DFS over each directory's children\n"+
							"  sorted as names. A mismatch here means walkLess and Walk disagree.",
							i, got[i], want[i])
					}
				}
			})
		}
	}
}

// describeSetDiff reports paths present in one side and not the other, ignoring
// order. Empty means the two describe the same tree.
func describeSetDiff(got, want []seedEntry) string {
	index := func(entries []seedEntry) map[seedEntry]int {
		m := make(map[seedEntry]int, len(entries))
		for _, e := range entries {
			m[e]++
		}
		return m
	}
	g, w := index(got), index(want)

	var onlyPlanned, onlyOnDisk []string
	for e, n := range g {
		if w[e] < n {
			onlyPlanned = append(onlyPlanned, fmt.Sprintf("%s (dir=%t)", e.RelPath, e.IsDir))
		}
	}
	for e, n := range w {
		if g[e] < n {
			onlyOnDisk = append(onlyOnDisk, fmt.Sprintf("%s (dir=%t)", e.RelPath, e.IsDir))
		}
	}
	if len(onlyPlanned) == 0 && len(onlyOnDisk) == 0 {
		return ""
	}
	sort.Strings(onlyPlanned)
	sort.Strings(onlyOnDisk)

	msg := fmt.Sprintf("  planned %d entries, on-disk %d\n", len(got), len(want))
	if len(onlyPlanned) > 0 {
		msg += fmt.Sprintf("  only in the plan (%d): %s\n", len(onlyPlanned), sample(onlyPlanned))
	}
	if len(onlyOnDisk) > 0 {
		msg += fmt.Sprintf("  only on disk (%d): %s\n", len(onlyOnDisk), sample(onlyOnDisk))
	}
	return msg
}

func sample(s []string) string {
	if len(s) <= 5 {
		return fmt.Sprint(s)
	}
	return fmt.Sprintf("%v ... and %d more", s[:5], len(s)-5)
}

// A guard against the test above passing vacuously: if planSeedEntries returned
// nil and BuildSeedContext somehow produced nothing, every comparison succeeds.
func TestPlanSeedEntriesProducesARealTree(t *testing.T) {
	got, fileCount := planSeedEntries(1000, 8, rand.New(rand.NewSource(42)))
	if len(got) < 100 {
		t.Fatalf("planned only %d entries for 1000 files; the equivalence test would pass vacuously", len(got))
	}
	var dirs, files int
	for _, e := range got {
		if e.IsDir {
			dirs++
		} else {
			files++
		}
	}
	if dirs == 0 || files == 0 {
		t.Fatalf("planned %d dirs and %d files; want both", dirs, files)
	}
	if fileCount != files {
		t.Fatalf("returned file count %d, but %d entries are files; the count is what the\n"+
			"caller reports as the seed size", fileCount, files)
	}
}

// The same seed must plan the same tree every time. Without this a run is not
// reproducible even against itself, never mind against the other transport.
func TestPlanSeedEntriesIsDeterministic(t *testing.T) {
	a, aCount := planSeedEntries(2000, 9, rand.New(rand.NewSource(7)))
	b, bCount := planSeedEntries(2000, 9, rand.New(rand.NewSource(7)))
	if len(a) != len(b) || aCount != bCount {
		t.Fatalf("same seed planned %d entries (%d files) then %d entries (%d files)",
			len(a), aCount, len(b), bCount)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("same seed diverged at entry %d: %+v then %+v", i, a[i], b[i])
		}
	}
}

// Different seeds must plan different trees, or --seed is decorative and the
// determinism test above proves nothing.
func TestPlanSeedEntriesVariesWithTheSeed(t *testing.T) {
	a, _ := planSeedEntries(2000, 9, rand.New(rand.NewSource(7)))
	b, _ := planSeedEntries(2000, 9, rand.New(rand.NewSource(8)))
	same := len(a) == len(b)
	if same {
		for i := range a {
			if a[i] != b[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("two different seeds planned an identical tree")
	}
}

// Every file must be preceded by the directory that contains it. The entry list
// is replayed to create the tree, so a child before its parent is a CREATE
// against a directory that does not exist yet.
func TestPlanSeedEntriesEmitsParentsBeforeChildren(t *testing.T) {
	entries, _ := planSeedEntries(3000, 10, rand.New(rand.NewSource(99)))
	seen := map[string]bool{"": true, ".": true}
	for i, e := range entries {
		if parent := parentOf(e.RelPath); !seen[parent] {
			t.Fatalf("entry %d %q comes before its parent %q was emitted", i, e.RelPath, parent)
		}
		if e.IsDir {
			seen[e.RelPath] = true
		}
	}
}

func parentOf(rel string) string {
	for i := len(rel) - 1; i >= 0; i-- {
		if rel[i] == '/' {
			return rel[:i]
		}
	}
	return ""
}

// The userspace generation path must not create anything under the target on
// the local filesystem. A Mac running this has no mount at all, so a single
// MkdirAll is the difference between working and not.
//
// The test drives RunContext far enough to reach the seed phase and no further:
// the connect that follows fails because nothing listens on port 1, which is
// the expected outcome. What matters is what is on disk when it does.
//
// This passes against the shipped code rather than driving a change -- the
// userspace branch already plans in memory. It is here as the guard that keeps
// it that way, because the regression it catches (a stray MkdirAll, a seed
// rebuilt "just for the manifest") is invisible on Linux, where the target is
// mounted and a local write silently succeeds.
func TestUserspaceGenerationTouchesNoLocalSeed(t *testing.T) {
	target := t.TempDir()

	cfg := Config{
		Target:          filepath.Join(target, "tree"),
		Roster:          Roster{Domain: "example.test", Roles: map[string]string{"owner": "alice"}},
		Scale:           Scales["small"],
		Workers:         4,
		Seed:            42,
		Transport:       "userspace",
		Server:          "127.0.0.1:1", // nothing listens on port 1
		Export:          "/export",
		Connections:     1,
		SafetyPrincipal: "tester@example.test",
	}

	// The connect is expected to fail. The assertion is about the filesystem.
	if err := RunContext(t.Context(), cfg); err == nil {
		t.Fatal("RunContext succeeded against a dead port; the test is not reaching the connect")
	}

	seedDir := filepath.Join(cfg.Target, ".seed")
	if _, err := os.Stat(seedDir); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%s) = %v; the userspace path must never create a seed on disk", seedDir, err)
	}
	if entries, err := os.ReadDir(target); err == nil && len(entries) > 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the userspace path created %v under the target; it must create nothing locally", names)
	}
}
