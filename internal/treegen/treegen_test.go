package treegen

import (
	"context"
	"encoding/json"
	"io/fs"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the path-counting and manifest-recording logic on a
// local tmpdir. nfs4acl.SetACL fails there (no system.nfs4_acl support), which
// is harmless: the stamp failure is counted in Failures and every code path
// under test — path counting, department/subtree-root enumeration, manifest
// composition — runs identically. Assertions therefore cover TotalPaths and
// the manifest, never Applied.

func testRoleMap() map[string]string {
	roles := []string{
		"group_array", "group_primary", "group_readonly", "group_secondary",
		"owner_primary", "owner_secondary", "owner_tertiary", "service_account",
		"user_auditor", "user_collaborator", "user_denied",
	}
	m := make(map[string]string, len(roles))
	for _, r := range roles {
		m[r] = r + "@example.test"
	}
	return m
}

type testManifest struct {
	TotalPaths  int64          `json:"total_paths"`
	Applied     int64          `json:"applied"`
	Departments []SubtreeEntry `json:"departments"`
	Subtrees    []SubtreeEntry `json:"subtrees"`
	Outliers    []struct {
		Path     string `json:"path"`
		Scenario string `json:"scenario"`
	} `json:"file_outliers"`
}

func readManifest(t *testing.T, path string) testManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m testManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return m
}

// walkPaths returns every non-symlink path under root except root itself and
// the manifest file the generator writes.
func walkPaths(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && filepath.Base(path) == "acl_manifest.json" {
			return nil
		}
		out[path] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func generate(t *testing.T, copies, seedFiles, filesPerSubtree int) (string, *StampResult) {
	t.Helper()
	root := t.TempDir()
	seed := filepath.Join(root, ".seed")
	tree := filepath.Join(root, "tree")

	rng := rand.New(rand.NewSource(7))
	if _, err := BuildSeed(seed, seedFiles, 5, rng); err != nil {
		t.Fatalf("build seed: %v", err)
	}
	res, err := FanOutAndStamp(seed, tree, copies, 4, rng, testRoleMap(), "", filesPerSubtree, ManifestMeta{})
	if err != nil {
		t.Fatalf("fan-out+stamp: %v", err)
	}
	return tree, res
}

func TestTotalPathsMatchesTree(t *testing.T) {
	tree, res := generate(t, 4, 30, 4)
	m := readManifest(t, res.ManifestPath)

	paths := walkPaths(t, tree)
	if int64(len(paths)) != res.TotalPaths {
		t.Errorf("TotalPaths = %d, walk found %d paths", res.TotalPaths, len(paths))
	}
	if m.TotalPaths != res.TotalPaths {
		t.Errorf("manifest total_paths = %d, result = %d", m.TotalPaths, res.TotalPaths)
	}

	// Outliers are stamped twice, so stamp operations must exceed the path
	// count whenever any outlier was selected — and total_paths must not.
	if len(m.Outliers) == 0 {
		t.Fatal("expected at least one file outlier")
	}
	wantStamps := m.TotalPaths + int64(len(m.Outliers))
	var stamps int64
	for _, s := range res.Scenarios {
		stamps += int64(s.Total)
	}
	if stamps != wantStamps {
		t.Errorf("scenario stamp total = %d, want %d (paths %d + outliers %d)",
			stamps, wantStamps, m.TotalPaths, len(m.Outliers))
	}
}

func TestFilesPerSubtreeDoesNotChangeTotalPaths(t *testing.T) {
	_, withOutliers := generate(t, 4, 30, 4)
	_, without := generate(t, 4, 30, 0)
	if withOutliers.TotalPaths != without.TotalPaths {
		t.Errorf("total_paths differs with outliers (%d) and without (%d)",
			withOutliers.TotalPaths, without.TotalPaths)
	}
}

func TestManifestRecordsDepartmentsAndSubtreeRoots(t *testing.T) {
	tree, res := generate(t, 6, 20, 2)
	m := readManifest(t, res.ManifestPath)

	if len(m.Departments) == 0 {
		t.Fatal("manifest recorded no department directories")
	}
	if len(m.Subtrees) != 6 {
		t.Fatalf("manifest recorded %d subtrees, want 6", len(m.Subtrees))
	}

	paths := walkPaths(t, tree)
	for _, d := range m.Departments {
		if !paths[d.Path] {
			t.Errorf("department %s in manifest but not on disk", d.Path)
		}
		if d.Scenario == "" {
			t.Errorf("department %s has no scenario recorded", d.Path)
		}
	}
	// Every subtree root's parent must be a recorded department.
	dept := map[string]bool{}
	for _, d := range m.Departments {
		dept[d.Path] = true
	}
	for _, s := range m.Subtrees {
		if !paths[s.Path] {
			t.Errorf("subtree root %s in manifest but not on disk", s.Path)
		}
		if s.Scenario == "" {
			t.Errorf("subtree root %s has no scenario recorded", s.Path)
		}
		if !dept[filepath.Dir(s.Path)] {
			t.Errorf("parent of subtree %s not recorded as a department", s.Path)
		}
	}
}

func TestDepartmentScenariosDeterministic(t *testing.T) {
	_, a := generate(t, 5, 20, 2)
	_, b := generate(t, 5, 20, 2)
	ma := readManifest(t, a.ManifestPath)
	mb := readManifest(t, b.ManifestPath)
	if len(ma.Departments) != len(mb.Departments) {
		t.Fatalf("department count differs: %d vs %d", len(ma.Departments), len(mb.Departments))
	}
	for i := range ma.Departments {
		if ma.Departments[i].Scenario != mb.Departments[i].Scenario {
			t.Errorf("department %d scenario differs: %s vs %s",
				i, ma.Departments[i].Scenario, mb.Departments[i].Scenario)
		}
	}
	if a.TotalPaths != b.TotalPaths {
		t.Errorf("total_paths not reproducible: %d vs %d", a.TotalPaths, b.TotalPaths)
	}
}

func TestStampACLsCountsDepartmentsAndRootsOnce(t *testing.T) {
	tree, _ := generate(t, 4, 20, 3)
	// Restamp the existing tree, the --acls-only path.
	rng := rand.New(rand.NewSource(11))
	res, err := StampACLs(tree, testRoleMap(), "", 3, 4, rng, false, ManifestMeta{})
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	m := readManifest(t, res.ManifestPath)

	paths := walkPaths(t, tree)
	if int64(len(paths)) != res.TotalPaths {
		t.Errorf("restamp TotalPaths = %d, walk found %d paths", res.TotalPaths, len(paths))
	}
	if len(m.Departments) == 0 {
		t.Error("restamp manifest recorded no department directories")
	}
	for _, d := range m.Departments {
		if !paths[d.Path] {
			t.Errorf("department %s in manifest but not on disk", d.Path)
		}
	}
	if len(m.Outliers) == 0 {
		t.Error("expected file outliers in restamp manifest")
	}
	var stamps int64
	for _, s := range res.Scenarios {
		stamps += int64(s.Total)
	}
	if stamps != m.TotalPaths+int64(len(m.Outliers)) {
		t.Errorf("restamp stamp total = %d, want %d", stamps, m.TotalPaths+int64(len(m.Outliers)))
	}
}

func TestDepartmentDirsUniqueAndSorted(t *testing.T) {
	dests := []string{"/t/b/p1", "/t/a/p1", "/t/b/p2", "/t/a/p2"}
	got := departmentDirs(dests)
	want := []string{"/t/a", "/t/b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestFanOutAndStampCancelledReturnsError(t *testing.T) {
	root := t.TempDir()
	seed := filepath.Join(root, ".seed")
	tree := filepath.Join(root, "tree")

	rng := rand.New(rand.NewSource(7))
	if _, err := BuildSeed(seed, 20, 4, rng); err != nil {
		t.Fatalf("build seed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := FanOutAndStampContext(ctx, seed, tree, 4, 4, rng, testRoleMap(), "", 0, ManifestMeta{})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !isContextError(err) {
		t.Fatalf("expected context error, got: %v", err)
	}

	manifest := filepath.Join(tree, "acl_manifest.json")
	if _, statErr := os.Stat(manifest); statErr == nil {
		t.Error("manifest should not be written after cancellation")
	}
}

func TestStampACLsCancelledReturnsError(t *testing.T) {
	tree, _ := generate(t, 4, 20, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rng := rand.New(rand.NewSource(7))
	_, err := StampACLsContext(ctx, tree, testRoleMap(), "", 0, 4, rng, false, ManifestMeta{})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !isContextError(err) {
		t.Fatalf("expected context error, got: %v", err)
	}
}

func isContextError(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// Plan-destinations tests (from generate-tree-1b-scaling).

func TestPlanDestinationsShallowCount(t *testing.T) {
	for _, n := range []int{10, 50, 200, 5000} {
		rng := rand.New(rand.NewSource(42))
		dests := planDestinationsShallow("/root", n, rng)
		if len(dests) != n {
			t.Errorf("shallow(%d): got %d destinations", n, len(dests))
		}
	}
}

func TestPlanDestinationsDeepCount(t *testing.T) {
	for _, n := range []int{1, 1024, 10001, 50000, 500000} {
		rng := rand.New(rand.NewSource(42))
		dests := planDestinationsDeep("/root", n, rng)
		if len(dests) != n {
			t.Errorf("deep(%d): got %d destinations", n, len(dests))
		}
	}
}

func TestPlanDestinationsDeepMaxWidth(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	dests := planDestinationsDeep("/root", 500000, rng)

	width := map[string]int{}
	for _, d := range dests {
		parent := filepath.Dir(d)
		width[parent]++
	}

	for dir, w := range width {
		if w > 500 {
			t.Errorf("directory %s has width %d (max 500)", dir, w)
		}
	}
}

func TestPlanDestinationsAutoSelectDeep(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	dests := planDestinations("/root", 10001, rng)
	if len(dests) != 10001 {
		t.Fatalf("expected 10001, got %d", len(dests))
	}

	depth := func(p string) int {
		n := 0
		for p != "/root" && p != "." && p != "/" {
			n++
			p = filepath.Dir(p)
		}
		return n
	}
	if d := depth(dests[0]); d < 4 {
		t.Errorf("expected depth ≥4 for deep layout, got %d", d)
	}
}

func TestPlanDestinationsAutoSelectShallow(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	dests := planDestinations("/root", 10000, rng)
	if len(dests) != 10000 {
		t.Fatalf("expected 10000, got %d", len(dests))
	}
}

func TestPlanDestinationsDeterminism(t *testing.T) {
	for _, n := range []int{100, 50000} {
		a := planDestinations("/root", n, rand.New(rand.NewSource(99)))
		b := planDestinations("/root", n, rand.New(rand.NewSource(99)))
		if len(a) != len(b) {
			t.Fatalf("determinism(%d): length mismatch", n)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("determinism(%d): differ at %d: %s vs %s", n, i, a[i], b[i])
				break
			}
		}
	}
}

func TestScaleColossal(t *testing.T) {
	s, ok := Scales["colossal"]
	if !ok {
		t.Fatal("colossal scale not defined")
	}
	if s.Copies != 500000 {
		t.Errorf("colossal copies: got %d, want 500000", s.Copies)
	}
	if s.SeedFiles != 2000 {
		t.Errorf("colossal seed files: got %d, want 2000", s.SeedFiles)
	}
	if s.MaxDepth != 18 {
		t.Errorf("colossal max depth: got %d, want 18", s.MaxDepth)
	}
}

// An explicit --safety-principal wins over anything derived. It is the escape
// hatch for exactly the case that motivates this: a Mac whose local username
// the array has never heard of.
func TestSafetyPrincipalForHonoursTheOverride(t *testing.T) {
	cfg := Config{
		SafetyPrincipal: "operator@corp.example.com",
		Roster:          Roster{Domain: "corp.example.com"},
	}
	got, err := safetyPrincipalFor(cfg)
	if err != nil {
		t.Fatalf("safetyPrincipalFor: %v", err)
	}
	if got != cfg.SafetyPrincipal {
		t.Fatalf("got %q, want the override %q", got, cfg.SafetyPrincipal)
	}
}

// The override wins even when nothing could be derived, which is the whole
// point of it: on a host with no resolvable account it is the only way through.
func TestSafetyPrincipalForOverrideWinsWithNoDomain(t *testing.T) {
	cfg := Config{SafetyPrincipal: "operator@example.test"}
	got, err := safetyPrincipalFor(cfg)
	if err != nil {
		t.Fatalf("safetyPrincipalFor: %v", err)
	}
	if got != cfg.SafetyPrincipal {
		t.Fatalf("got %q, want the override %q", got, cfg.SafetyPrincipal)
	}
}

func TestSafetyPrincipalForDerivesFromTheRunningUser(t *testing.T) {
	cfg := Config{Roster: Roster{Domain: "example.test"}}
	got, err := safetyPrincipalFor(cfg)
	if err != nil {
		t.Fatalf("safetyPrincipalFor: %v", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Skipf("no current user on this host: %v", err)
	}
	if want := u.Username + "@example.test"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The failure has to name the flag. A derived principal the array cannot
// resolve is the single most likely way a first macOS run goes wrong, and
// "cannot determine current user" gives an operator nothing to act on.
func TestSafetyPrincipalErrorNamesTheOverrideFlag(t *testing.T) {
	cfg := Config{Roster: Roster{Domain: ""}}
	_, err := safetyPrincipalFor(cfg)
	if err == nil {
		t.Fatal("an empty roster domain produced no error")
	}
	if !strings.Contains(err.Error(), "--safety-principal") {
		t.Fatalf("error = %q, want it to name --safety-principal", err)
	}
}

func TestBuildRoleMapShippedRosters(t *testing.T) {
	paths, err := filepath.Glob("../../examples/principals_*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no shipped rosters found: %v", err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var roster Roster
		if err := json.Unmarshal(data, &roster); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if roster.Domain == "" {
			continue // not a generate-tree roster (e.g. the Windows one)
		}
		for role, got := range buildRoleMap(roster) {
			name := roster.Roles[role]
			want := name + "@" + roster.Domain
			if strings.HasSuffix(name, "@") {
				want = name
			}
			if got != want || strings.Contains(got, "@@") {
				t.Errorf("%s: role %s = %q, want %q", filepath.Base(p), role, got, want)
			}
		}
	}
}

func TestPrincipalSpecialPassesThrough(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"OWNER@", "OWNER@"},
		{"GROUP@", "GROUP@"},
		{"EVERYONE@", "EVERYONE@"},
		{"alice", "alice@example.net"},
	} {
		if got := principal(tc.name, "example.net"); got != tc.want {
			t.Errorf("principal(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDropSpecialDenies(t *testing.T) {
	got := dropSpecialDenies([]string{
		"D:fd:EVERYONE@:rwa",
		"A:fd:EVERYONE@:rxtncy",
		"D:fdg:GROUP@:rwa",
		"D:fd:alice@example.net:rwa",
		"A::OWNER@:rwaDxtTcCoy",
	})
	want := []string{"A:fd:EVERYONE@:rxtncy", "D:fd:alice@example.net:rwa", "A::OWNER@:rwaDxtTcCoy"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNoSpecialDenyInAnyScenario(t *testing.T) {
	for _, p := range []string{"principals_wellknown.json", "principals_example_nfs.json"} {
		data, err := os.ReadFile(filepath.Join("../../examples", p))
		if err != nil {
			t.Fatal(err)
		}
		var roster Roster
		if err := json.Unmarshal(data, &roster); err != nil {
			t.Fatal(err)
		}
		roleMap := buildRoleMap(roster)
		for _, s := range append(DirScenarios(), FileScenarios()...) {
			enc, err := preEncodeScenario(s, roleMap, "builder@example.net")
			if err != nil {
				t.Fatalf("%s/%s: %v", p, s.Name, err)
			}
			for _, a := range append(enc.dirACEs, enc.fileACEs...) {
				parts := strings.SplitN(a, ":", 4)
				if parts[0] == "D" && strings.HasSuffix(parts[2], "@") {
					t.Errorf("%s/%s: special-principal deny %q would lock out the builder", p, s.Name, a)
				}
			}
		}
	}
}

func TestScenariosLosingDenies(t *testing.T) {
	named := buildRoleMap(Roster{Domain: "example.net", Roles: map[string]string{"user_denied": "bob"}})
	if got := scenariosLosingDenies(named); len(got) != 0 {
		t.Errorf("named roster: got %v, want none", got)
	}
	special := buildRoleMap(Roster{Domain: "example.net", Roles: map[string]string{"user_denied": "EVERYONE@"}})
	if got := scenariosLosingDenies(special); len(got) == 0 {
		t.Error("special deny roster: got none, want the deny scenarios")
	}
}
