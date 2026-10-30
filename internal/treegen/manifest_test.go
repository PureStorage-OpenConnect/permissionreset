package treegen

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestReadManifestReturnsShapeAndCount(t *testing.T) {
	root := t.TempDir()
	body := `{"version":1,"generated_target":"` + root + `","shape":{"copies":4,"seed_files":200,"max_depth":14,"seed":42,"files_per_subtree":4},"total_paths":16000,"applied":16000,"failures":0,"subtrees":[]}`
	if err := os.WriteFile(filepath.Join(root, "acl_manifest.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalPaths != 16000 || got.Shape == nil || got.Shape.Copies != 4 {
		t.Fatalf("manifest = %+v", got)
	}
}

func TestReadManifestAcceptsLegacyMarkerForSafetyButReportsNoShape(t *testing.T) {
	root := t.TempDir()
	body := `{"generated_target":"` + root + `","total_paths":900,"applied":900,"failures":0,"subtrees":[]}`
	if err := os.WriteFile(filepath.Join(root, "acl_manifest.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalPaths != 900 || got.Shape != nil {
		t.Fatalf("legacy manifest = %+v, want count 900 and nil shape", got)
	}
}

func TestWriteManifestRoundTripsShapeAndOutliers(t *testing.T) {
	root := t.TempDir()
	want := Manifest{
		Version:         ManifestVersion,
		GeneratedTarget: root,
		Domain:          "example.test",
		Roles:           map[string]string{"owner": "alice@example.test"},
		Shape:           &ManifestShape{Copies: 7, SeedFiles: 100, MaxDepth: 10, Seed: 42, FilesPerSubtree: 4},
		TotalPaths:      70,
		Applied:         70,
		Subtrees:        []SubtreeEntry{{Path: filepath.Join(root, "ops", "alpha_00"), Scenario: "deny_first"}},
		FileOutliers:    []FileOutlier{{Path: filepath.Join(root, "ops", "alpha_00", "f.txt"), Scenario: "append_only"}},
	}
	if err := writeManifestTo(filepath.Join(root, ManifestName), want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Shape == nil || *got.Shape != *want.Shape {
		t.Fatalf("shape = %+v", got.Shape)
	}
	if len(got.Subtrees) != 1 || got.Subtrees[0].Scenario != "deny_first" {
		t.Fatalf("subtrees = %+v", got.Subtrees)
	}
	if len(got.FileOutliers) != 1 || got.FileOutliers[0].Scenario != "append_only" {
		t.Fatalf("outliers = %+v", got.FileOutliers)
	}
	if got.Version != ManifestVersion || got.Roles["owner"] != "alice@example.test" {
		t.Fatalf("manifest = %+v", got)
	}
	// The atomic write must not leave its temp file behind.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "acl_manifest.json" {
			t.Fatalf("stray file after write: %s", e.Name())
		}
	}
}

func TestReadManifestReportsMissingAndMalformed(t *testing.T) {
	root := t.TempDir()
	if _, err := ReadManifest(root); !os.IsNotExist(err) {
		t.Fatalf("missing manifest err = %v, want IsNotExist", err)
	}
	if err := os.WriteFile(filepath.Join(root, "acl_manifest.json"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(root); err == nil {
		t.Fatal("malformed manifest accepted")
	}
}

// Generation on a local tmpdir cannot set NFSv4 ACLs, so every stamp fails and
// is counted. The manifest is still written, which is what this pins: the shape
// and roster reach the file, and a re-stamp does not lose the shape.
func TestGenerationRecordsShapeAndRestampPreservesIt(t *testing.T) {
	root := t.TempDir()
	shape := &ManifestShape{Copies: 2, SeedFiles: 5, MaxDepth: 3, Seed: 1, FilesPerSubtree: 1}
	roster, roleMap := seedTree(t, root, shape)
	rng := rand.New(rand.NewSource(2))

	m, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != ManifestVersion || m.Shape == nil || *m.Shape != *shape {
		t.Fatalf("manifest = %+v shape %+v", m, m.Shape)
	}
	if m.Domain != "example.test" || m.Roles["owner"] != "alice@example.test" {
		t.Fatalf("roster not recorded: %+v", m)
	}
	if len(m.Subtrees) != 2 || m.GeneratedTarget != root {
		t.Fatalf("manifest = %+v", m)
	}

	// A re-stamp asserts no shape of its own; the recorded one must survive.
	if _, err := StampACLs(root, roleMap, "", 1, 2, rng, false, ManifestMeta{Roster: roster}); err != nil {
		t.Fatal(err)
	}
	after, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Shape == nil || *after.Shape != *shape {
		t.Fatalf("shape after re-stamp = %+v, want %+v", after.Shape, shape)
	}
}

// seedTree builds a two-subtree tree with ACLs stamped (and, on a local
// filesystem, failing) so the manifest paths can be exercised offline.
func seedTree(t *testing.T, root string, shape *ManifestShape) (Roster, map[string]string) {
	t.Helper()
	seed := filepath.Join(root, ".seed")
	rng := rand.New(rand.NewSource(1))
	if _, err := BuildSeed(seed, 5, 3, rng); err != nil {
		t.Fatal(err)
	}
	roster := Roster{Domain: "example.test", Roles: map[string]string{"owner": "alice"}}
	roleMap := buildRoleMap(roster)
	if _, err := FanOutAndStamp(seed, root, 2, 2, rng, roleMap, "", 1,
		ManifestMeta{Roster: roster, Shape: shape}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(seed); err != nil {
		t.Fatal(err)
	}
	return roster, roleMap
}

// A manifest that cannot be written must fail the run. Silently missing, it
// reads as "not a generated tree" — the one conclusion that lets a later caller
// delete the tree.
func TestGenerationFailsWhenTheManifestCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	// A directory in the manifest's place makes the final rename fail while
	// leaving tree creation itself untouched.
	if err := os.Mkdir(filepath.Join(root, ManifestName), 0755); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(root, ".seed")
	rng := rand.New(rand.NewSource(1))
	if _, err := BuildSeed(seed, 5, 3, rng); err != nil {
		t.Fatal(err)
	}
	roster := Roster{Domain: "example.test"}
	_, err := FanOutAndStamp(seed, root, 2, 2, rng, buildRoleMap(roster), "", 1,
		ManifestMeta{Roster: roster, Shape: &ManifestShape{Copies: 2}})
	if err == nil {
		t.Fatal("fan-out+stamp reported success with no manifest written")
	}
}

func TestReStampFailsWhenTheManifestCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	roster, roleMap := seedTree(t, root, &ManifestShape{Copies: 2, SeedFiles: 5, MaxDepth: 3, Seed: 1, FilesPerSubtree: 1})
	if err := os.Remove(filepath.Join(root, ManifestName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ManifestName), 0755); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(2))
	if _, err := StampACLs(root, roleMap, "", 1, 2, rng, false, ManifestMeta{Roster: roster}); err == nil {
		t.Fatal("re-stamp reported success with no manifest written")
	}
}

// A caller that states a shape gets that shape, per ManifestMeta's contract.
func TestReStampHonorsAnExplicitShapeOverTheRecordedOne(t *testing.T) {
	root := t.TempDir()
	recorded := &ManifestShape{Copies: 2, SeedFiles: 5, MaxDepth: 3, Seed: 1, FilesPerSubtree: 1}
	roster, roleMap := seedTree(t, root, recorded)
	stated := &ManifestShape{Copies: 9, SeedFiles: 11, MaxDepth: 4, Seed: 7, FilesPerSubtree: 2}
	rng := rand.New(rand.NewSource(2))
	if _, err := StampACLs(root, roleMap, "", 1, 2, rng, false, ManifestMeta{Roster: roster, Shape: stated}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Shape == nil || *got.Shape != *stated {
		t.Fatalf("shape = %+v, want the stated %+v", got.Shape, stated)
	}
}

// A dry run reports what it would do and writes nothing, so it stays usable
// against a tree the caller cannot write to.
func TestStampACLsDryRunWritesNoManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ops", "alpha_00", "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	roster := Roster{Domain: "example.test", Roles: map[string]string{"owner": "alice"}}
	rng := rand.New(rand.NewSource(3))
	if _, err := StampACLs(root, buildRoleMap(roster), "", 1, 2, rng, true,
		ManifestMeta{Roster: roster, Shape: &ManifestShape{Copies: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ManifestName)); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote a manifest (stat err = %v)", err)
	}
}

func TestShapeFromConfig(t *testing.T) {
	cfg := Config{
		Scale:           Scale{Copies: 4, SeedFiles: 200, MaxDepth: 14},
		Seed:            42,
		FilesPerSubtree: 4,
	}
	got := ShapeFromConfig(cfg)
	if got == nil || *got != (ManifestShape{Copies: 4, SeedFiles: 200, MaxDepth: 14, Seed: 42, FilesPerSubtree: 4}) {
		t.Fatalf("shape = %+v", got)
	}
}

// The default keeps every existing Linux invocation writing the manifest
// exactly where it does today: inside the tree it describes.
func TestResolveManifestPathDefaultsBesideALocalTarget(t *testing.T) {
	target := t.TempDir()
	got := resolveManifestPath("", target)
	if want := filepath.Join(target, ManifestName); got != want {
		t.Fatalf("resolveManifestPath = %q, want %q", got, want)
	}
}

// A mount-free run passes "" -- there is no local directory to put it beside --
// and gets the manifest in the working directory. The client cannot write it
// over the wire: the op set has no OP_WRITE, so OPEN(CREATE) yields an empty
// file and there is no way to put bytes in it.
func TestResolveManifestPathFallsBackToWorkingDirectory(t *testing.T) {
	// Absolute, not a bare basename: this path is recorded in the manifest so a
	// later reader can find it, and a basename relative to a working directory
	// the reader does not know says nothing.
	want := filepath.Join(mustGetwd(t), ManifestName)
	if got := resolveManifestPath("", ""); got != want {
		t.Fatalf("resolveManifestPath = %q, want %q", got, want)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// The regression finding 12 names: a server-side path must never be treated as
// a local one. The caller passes "" for a mount-free run, so even a working
// directory that happens to contain a directory of the same name changes
// nothing.
func TestResolveManifestPathIgnoresAColocatedDirectoryOfTheSameName(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bigdata"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(dir)

	want := filepath.Join(mustGetwd(t), ManifestName)
	if got := resolveManifestPath("", ""); got != want {
		t.Fatalf("resolveManifestPath = %q, want %q -- a same-named local directory must not win", got, want)
	}
}

func TestResolveManifestPathHonoursAnExplicitPath(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "somewhere", "else.json")
	if got := resolveManifestPath(explicit, t.TempDir()); got != explicit {
		t.Fatalf("resolveManifestPath = %q, want the explicit %q", got, explicit)
	}
}

// writeManifestTo writes to a full file path, creating parent directories,
// atomically, and leaving no temp file behind.
func TestWriteManifestToFullPath(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "nested", "custom.json")
	m := Manifest{Version: ManifestVersion, GeneratedTarget: "/export/tree", TotalPaths: 7}

	if err := writeManifestTo(dst, m); err != nil {
		t.Fatalf("writeManifestTo: %v", err)
	}

	got := readManifest(t, dst)
	if got.TotalPaths != 7 {
		t.Fatalf("round-tripped TotalPaths %d, want 7", got.TotalPaths)
	}

	siblings, err := os.ReadDir(filepath.Dir(dst))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(siblings) != 1 {
		var names []string
		for _, s := range siblings {
			names = append(names, s.Name())
		}
		t.Fatalf("directory holds %v; the atomic rename must leave no temp file behind", names)
	}
}

// A manifest that cannot be written must say so. Silence here is the dangerous
// outcome and writeManifest's own doc comment says why: a missing manifest
// reads as "not a generated tree", which is the one conclusion that lets a
// caller delete the tree.
func TestWriteManifestToReportsAnUnwritablePath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "in-the-way")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := writeManifestTo(filepath.Join(blocker, "acl_manifest.json"), Manifest{Version: ManifestVersion})
	if err == nil {
		t.Fatal("writing under a regular file succeeded; an unwritable manifest must be an error")
	}
}

// A manifest written away from the tree records where it went. Beside the tree
// it stays empty, because the tree already leads to it and a redundant absolute
// path is one more thing that can be wrong after the tree is moved.
func TestManifestRecordsItsOwnPathOnlyWhenItIsNotBesideTheTree(t *testing.T) {
	beside := buildManifest("/export/tree",
		ManifestMeta{Roster: Roster{Domain: "d", Roles: map[string]string{"o": "a"}}},
		1, 1, 0, nil, nil, nil)
	if beside.ManifestPath != "" {
		t.Fatalf("ManifestPath = %q for a manifest beside its tree, want empty", beside.ManifestPath)
	}

	away := buildManifest("/export/tree",
		ManifestMeta{Roster: Roster{Domain: "d", Roles: map[string]string{"o": "a"}}, Path: "/somewhere/acl_manifest.json"},
		1, 1, 0, nil, nil, nil)
	if away.ManifestPath != "/somewhere/acl_manifest.json" {
		t.Fatalf("ManifestPath = %q, want the recorded path", away.ManifestPath)
	}
}

// --manifest applies on the kernel transport too, not only where the target is
// remote. It used to be threaded through the userspace branch alone, which made
// the same flag mean "honoured" or "silently ignored" depending on a transport
// the operator may not have typed.
func TestWriteManifestGoesBesideTheRootByDefault(t *testing.T) {
	root := t.TempDir()
	if err := writeManifestTo(resolveManifestPath("", root),
		Manifest{Version: ManifestVersion, GeneratedTarget: root}); err != nil {
		t.Fatalf("writeManifestTo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ManifestName)); err != nil {
		t.Fatalf("stat: %v; the default location must not move", err)
	}
}

// A re-stamp does not restate the shape, so it recovers the one already on
// disk. When --manifest moved the manifest, "on disk" is that path and not the
// tree root -- and looking beside the tree instead finds nothing and writes a
// shapeless manifest over the only record sweep --reuse-scratch can check.
func TestRecoverShapeFollowsAnExplicitManifestPath(t *testing.T) {
	root := t.TempDir()
	away := filepath.Join(t.TempDir(), "elsewhere", ManifestName)
	shape := &ManifestShape{Copies: 4, SeedFiles: 20, MaxDepth: 5, Seed: 7, FilesPerSubtree: 2}

	if err := writeManifestTo(away, Manifest{
		Version: ManifestVersion, GeneratedTarget: root, Shape: shape,
	}); err != nil {
		t.Fatal(err)
	}

	got := recoverShape(ManifestMeta{Path: away}, resolveManifestPath(away, root))
	if got.Shape == nil {
		t.Fatal("shape = nil: the re-stamp dropped the shape the first run recorded")
	}
	if *got.Shape != *shape {
		t.Fatalf("shape = %+v, want %+v", *got.Shape, *shape)
	}
}

// A shape the caller states outright is better evidence than one on disk.
func TestRecoverShapeKeepsAStatedShape(t *testing.T) {
	root := t.TempDir()
	onDisk := &ManifestShape{Copies: 4}
	stated := &ManifestShape{Copies: 99}
	if err := writeManifestTo(resolveManifestPath("", root), Manifest{Shape: onDisk}); err != nil {
		t.Fatal(err)
	}
	got := recoverShape(ManifestMeta{Shape: stated}, resolveManifestPath("", root))
	if got.Shape != stated {
		t.Fatalf("shape = %+v, want the stated %+v", got.Shape, stated)
	}
}

func TestResolveManifestPathDrivesBothTransports(t *testing.T) {
	root := t.TempDir()
	explicit := filepath.Join(t.TempDir(), "elsewhere.json")

	// The kernel call sites pass meta.Path, which is cfg.ManifestPath.
	if got := resolveManifestPath(explicit, root); got != explicit {
		t.Fatalf("resolveManifestPath = %q, want %q -- --manifest must win on the kernel path too", got, explicit)
	}
}

// Every call site records the same thing in manifest_path: the resolved path,
// and nothing at all when that is the default beside the tree, which the tree
// already leads to.
func TestRecordedManifestPathOmitsTheDefaultLocation(t *testing.T) {
	root := t.TempDir()
	if got := recordedManifestPath(resolveManifestPath("", root), root); got != "" {
		t.Fatalf("recordedManifestPath = %q, want \"\" for the default location", got)
	}
	away := filepath.Join(t.TempDir(), "elsewhere.json")
	if got := recordedManifestPath(resolveManifestPath(away, root), root); got != away {
		t.Fatalf("recordedManifestPath = %q, want %q", got, away)
	}
	// Mount-free: no tree to lead anywhere, so the path is always recorded.
	mountFree := resolveManifestPath("", "")
	if got := recordedManifestPath(mountFree, ""); got != mountFree {
		t.Fatalf("recordedManifestPath = %q, want %q", got, mountFree)
	}
}
