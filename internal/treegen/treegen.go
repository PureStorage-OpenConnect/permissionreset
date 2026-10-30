package treegen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"golang.org/x/sys/unix"
)

type Roster struct {
	Domain string            `json:"domain"`
	Roles  map[string]string `json:"roles"`
}

type Scale struct {
	Copies    int
	SeedFiles int
	MaxDepth  int
}

// scenarioStats accumulates per-scenario stamp counts across a run.
type scenarioStats struct {
	total   atomic.Int64
	applied atomic.Int64
}

// collectScenarioResult drains scenarioCounts into a sorted []ScenarioResult.
func collectScenarioResult(scenarioCounts *sync.Map) []ScenarioResult {
	var results []ScenarioResult
	scenarioCounts.Range(func(key, value any) bool {
		stats := value.(*scenarioStats)
		results = append(results, ScenarioResult{
			Name:    key.(string),
			Total:   int(stats.total.Load()),
			Applied: int(stats.applied.Load()),
		})
		return true
	})
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

var Scales = map[string]Scale{
	"small":    {Copies: 10, SeedFiles: 50, MaxDepth: 6},
	"medium":   {Copies: 50, SeedFiles: 100, MaxDepth: 10},
	"large":    {Copies: 200, SeedFiles: 200, MaxDepth: 14},
	"xlarge":   {Copies: 5000, SeedFiles: 200, MaxDepth: 14},
	"huge":     {Copies: 50000, SeedFiles: 2000, MaxDepth: 14},
	"colossal": {Copies: 500000, SeedFiles: 2000, MaxDepth: 18},
}

type Config struct {
	Target          string
	Roster          Roster
	Scale           Scale
	Workers         int
	Seed            int64
	ACLsOnly        bool
	NoACLs          bool
	DryRun          bool
	SafetyPrincipal string
	FilesPerSubtree int

	Transport   string // "kernel" (default) or "userspace"
	Server      string // NFS server hostname (userspace transport)
	Export      string // NFS export path (userspace transport)
	Connections int    // TCP connections to server (userspace transport)
	// ManifestPath is where acl_manifest.json goes. Empty means the default:
	// beside the tree root when there is a local one, otherwise the working
	// directory. It applies on both transports.
	ManifestPath string

	// Auth is the AUTH_SYS credential the userspace transport presents. Nil
	// means "build one from the running process". It is an *nfs41.AuthSys
	// rather than the four flag values so internal/treegen does not import
	// internal/cmdflags -- the command resolves the credential, this package
	// only carries it.
	Auth *nfs41.AuthSys
}

var extensions = []string{".txt", ".sh", ".dat", ".conf", ".log", ".csv", ".json", ".xml", ".py", ".md"}
var deptNames = []string{"engineering", "finance", "marketing", "ops", "legal", "hr", "data", "infra"}
var regionNames = []string{"us-west", "us-east", "eu-west", "eu-central", "apac-north", "apac-south", "latam", "mena"}
var teamNames = []string{
	"core", "platform", "ingest", "pipeline", "analytics", "storage", "network", "security",
	"compliance", "automation", "monitoring", "reporting", "integration", "migration", "testing", "release",
}
var projectNames = []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"}
var subdirNames = []string{"src", "docs", "config", "logs", "tmp", "archive", "reports", "scripts",
	"input", "output", "staging", "backup", "shared", "private", "templates"}

func principal(name, domain string) string {
	return name + "@" + domain
}

func buildRoleMap(roster Roster) map[string]string {
	m := make(map[string]string, len(roster.Roles))
	for role, name := range roster.Roles {
		m[role] = principal(name, roster.Domain)
	}
	return m
}

func detectSafetyPrincipal(domain string) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return "", fmt.Errorf("non-numeric uid %q: %w", u.Uid, err)
	}
	_ = uid
	return principal(u.Username, domain), nil
}

// safetyPrincipalFor decides the principal the safety ACE names -- the one ACE
// every generated object carries so the generating account can always come back
// and delete the tree.
//
// The derived value is the running account's username in the roster's NFSv4
// domain. That is right on a lab Linux client whose accounts come from the same
// directory the array uses, and wrong on a personal Mac, whose local username
// the array has never heard of. Deriving it is a local identity lookup rather
// than a filesystem dependency, so it works on macOS -- it just works to the
// wrong answer, which is a worse failure than not working at all.
//
// --safety-principal is the override, and both errors name it, because "cannot
// determine current user" gives an operator nothing to act on.
func safetyPrincipalFor(cfg Config) (string, error) {
	if cfg.SafetyPrincipal != "" {
		return cfg.SafetyPrincipal, nil
	}
	if cfg.Roster.Domain == "" {
		return "", fmt.Errorf("cannot derive a safety principal: the roster has no domain " +
			"(give --safety-principal NAME@DOMAIN)")
	}
	who, err := detectSafetyPrincipal(cfg.Roster.Domain)
	if err != nil {
		return "", fmt.Errorf("cannot derive a safety principal from the running account: %w "+
			"(give --safety-principal NAME@DOMAIN; on a machine not bound to the NFSv4 domain "+
			"the local account name is not one the array can resolve)", err)
	}
	return who, nil
}

func ValidatePrincipals(target string, roleMap map[string]string, safetyPrincipal string) error {
	tmp := filepath.Join(target, ".principal_probe")
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("cannot create probe file: %w", err)
	}
	f.Close()
	defer os.Remove(tmp)

	seen := make(map[string]bool)
	principals := []string{}
	for _, who := range roleMap {
		if !seen[who] {
			seen[who] = true
			principals = append(principals, who)
		}
	}
	if safetyPrincipal != "" && !seen[safetyPrincipal] {
		principals = append(principals, safetyPrincipal)
	}

	for _, who := range principals {
		a := nfs4acl.ACE{
			Type:  nfs4acl.TypeAllow,
			Flags: 0,
			Mask:  0x001F01FF, // full control
			Who:   who,
		}
		data := nfs4acl.Encode([]nfs4acl.ACE{a})
		if err := nfs4acl.SetACL(tmp, data); err != nil {
			// Retry with group flag — group principals need FlagGroup
			a.Flags = nfs4acl.FlagGroup
			data = nfs4acl.Encode([]nfs4acl.ACE{a})
			if err2 := nfs4acl.SetACL(tmp, data); err2 != nil {
				return fmt.Errorf("principal %q does not resolve: %w", who, err)
			}
		}
	}
	return nil
}

// Phase 1: Build seed tree

func BuildSeed(seedRoot string, nFiles, maxDepth int, rng *rand.Rand) (int, error) {
	return BuildSeedContext(context.Background(), seedRoot, nFiles, maxDepth, rng)
}

func BuildSeedContext(ctx context.Context, seedRoot string, nFiles, maxDepth int, rng *rand.Rand) (int, error) {
	entries, fileCount := planSeedEntries(nFiles, maxDepth, rng)

	if err := os.MkdirAll(seedRoot, 0755); err != nil {
		return 0, err
	}
	for i, e := range entries {
		// The old builder checked cancellation once per chain level and once
		// per hundred bulk files. Once per entry is finer than that and the
		// check is a load of an atomic word, which is nothing beside the
		// syscall on the next line.
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		full := filepath.Join(seedRoot, e.RelPath)
		if e.IsDir {
			if err := os.MkdirAll(full, 0755); err != nil {
				return 0, err
			}
			continue
		}
		if err := os.WriteFile(full, seedFileContent(e.RelPath), 0644); err != nil {
			return 0, err
		}
	}
	return fileCount, nil
}

// seedFileContent is what goes in a seed file. Nothing downstream reads it:
// copyTreeCached creates every fanned-out file with O_CREAT|O_TRUNC and closes
// it immediately, so each copy is zero bytes whatever the seed holds, and the
// seed itself is deleted once the fan-out returns, on success or failure alike
// (a BuildSeedContext that never finished can still leave one behind). It stays
// non-empty only so
// that a seed tree inspected by hand looks like files rather than placeholders.
//
// This is the one behavioural difference from the builder this function
// replaced, which wrote three different strings keyed on which loop created the
// file ("deep file level 3", "bulk file 40", "file 2 in mixed_007"). Those
// strings were derived from loop indices the planner does not carry, and
// reconstructing them by parsing the path back apart would put a second decoder
// of the tree's shape right where this change exists to remove one.
func seedFileContent(relPath string) []byte {
	return []byte("seed file " + relPath + "\n")
}

// seedEntry is a cached relative path from the seed tree.
// Collected once, reused across all copies to eliminate redundant Lstat calls.
type seedEntry struct {
	RelPath string
	IsDir   bool
}

// planSeedEntries generates the same []seedEntry that BuildSeedContext +
// collectSeedPaths would produce, but entirely in memory — no disk I/O, no
// mount needed. The structure is deterministic for a given (nFiles, maxDepth, rng).
func planSeedEntries(nFiles, maxDepth int, rng *rand.Rand) ([]seedEntry, int) {
	var entries []seedEntry
	add := func(rel string, isDir bool) {
		entries = append(entries, seedEntry{RelPath: rel, IsDir: isDir})
	}

	count := 0

	// Deep chain
	chainDepth := maxDepth
	if chainDepth > 12 {
		chainDepth = 12
	}
	current := ""
	for i := 0; i < chainDepth; i++ {
		name := fmt.Sprintf("deep_%02d", i)
		if current == "" {
			current = name
		} else {
			current = filepath.Join(current, name)
		}
		add(current, true)
		ext := extensions[rng.Intn(len(extensions))]
		add(filepath.Join(current, fmt.Sprintf("nested_%02d%s", i, ext)), false)
		count++
	}

	// Wide dir
	add("bulk_data", true)
	wideCount := nFiles / 4
	if wideCount > 500 {
		wideCount = 500
	}
	for i := 0; i < wideCount; i++ {
		ext := extensions[rng.Intn(len(extensions))]
		add(filepath.Join("bulk_data", fmt.Sprintf("file_%04d%s", i, ext)), false)
		count++
	}

	// Branching tree
	remaining := nFiles - count
	counter := &[1]int{0}
	branch := 0
	for counter[0] < remaining && branch < 200 {
		before := counter[0]
		planBranch("", fmt.Sprintf("mixed_%03d", branch), min(maxDepth-2, 6), remaining, counter, rng, &entries)
		branch++
		if counter[0] == before {
			break
		}
	}

	fileCount := 0
	for _, e := range entries {
		if !e.IsDir {
			fileCount++
		}
	}

	// Emit in filepath.Walk order, which is not the creation order the loops
	// above append in. collectSeedPaths -- the kernel path's equivalent of this
	// function -- walks the finished seed tree, and filepath.Walk is pre-order
	// DFS visiting each directory's children in sort.Strings order. Creation
	// order builds the deep chain first, then bulk_data, then mixed_NNN, but
	// bulk_data sorts before deep_00 and before mixed_000.
	//
	// Sorting here rather than emitting in this order directly keeps every rng
	// draw above in BuildSeedContext's exact sequence, which is the property
	// that actually decides the tree's shape. The sort only decides what order
	// the same entries are reported in.
	sort.Slice(entries, func(i, j int) bool {
		return walkLess(entries[i].RelPath, entries[j].RelPath)
	})
	return entries, fileCount
}

// walkLess orders two relative paths the way filepath.Walk visits them.
//
// This is deliberately not a string comparison of the whole path. '.' (0x2E)
// sorts before '/' (0x2F), so "a.txt" < "a/b" as strings -- but Walk descends
// into "a" before it reaches "a.txt", because it sorts each directory's
// children as names and only then recurses. Comparing component by component
// reproduces that; comparing the joined strings does not.
func walkLess(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	// One is a prefix of the other: the parent is visited first.
	return len(as) < len(bs)
}

func planBranch(base, name string, depth, budget int, counter *[1]int, rng *rand.Rand, entries *[]seedEntry) {
	if depth <= 0 || counter[0] >= budget {
		return
	}
	rel := filepath.Join(base, name)
	*entries = append(*entries, seedEntry{RelPath: rel, IsDir: true})

	remaining := budget - counter[0]
	if remaining < 2 {
		return
	}
	nFiles := rng.Intn(min(14, remaining)) + 2
	for i := 0; i < nFiles; i++ {
		if counter[0] >= budget {
			return
		}
		ext := extensions[rng.Intn(len(extensions))]
		*entries = append(*entries, seedEntry{RelPath: filepath.Join(rel, fmt.Sprintf("f_%02d%s", i, ext)), IsDir: false})
		counter[0]++
	}

	nSub := rng.Intn(min(4, depth)) + 1
	for i := 0; i < nSub; i++ {
		if counter[0] >= budget {
			return
		}
		subname := subdirNames[rng.Intn(len(subdirNames))] + fmt.Sprintf("_%d", i)
		planBranch(rel, subname, depth-1, budget, counter, rng, entries)
	}
}

func collectSeedPaths(seedRoot string) ([]seedEntry, error) {
	var entries []seedEntry
	err := filepath.Walk(seedRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(seedRoot, path)
		if rel == "." {
			return nil
		}
		entries = append(entries, seedEntry{RelPath: rel, IsDir: info.IsDir()})
		return nil
	})
	return entries, err
}

func copyTreeCached(entries []seedEntry, dst string) error {
	for _, e := range entries {
		target := filepath.Join(dst, e.RelPath)
		if e.IsDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		} else {
			fd, err := unix.Open(target, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			unix.Close(fd)
		}
	}
	return nil
}

// Phase 2: Fan-out

// planDestinations builds the destination layout without touching the filesystem.
// For copies > 10K it uses a 4-level deep layout to keep directory width ≤500;
// otherwise it uses the original 2-level dept/project layout.
func planDestinations(targetRoot string, nCopies int, rng *rand.Rand) []string {
	if nCopies > 10000 {
		return planDestinationsDeep(targetRoot, nCopies, rng)
	}
	return planDestinationsShallow(targetRoot, nCopies, rng)
}

func planDestinationsShallow(targetRoot string, nCopies int, rng *rand.Rand) []string {
	nDepts := max(2, nCopies/10)
	if nDepts > len(deptNames) {
		nDepts = len(deptNames)
	}
	perm := rng.Perm(len(deptNames))
	depts := make([]string, nDepts)
	for i := 0; i < nDepts; i++ {
		depts[i] = deptNames[perm[i]]
	}

	var dests []string
	for _, dept := range depts {
		deptPath := filepath.Join(targetRoot, dept)
		projsPerDept := max(1, nCopies/len(depts))
		for p := 0; p < projsPerDept && len(dests) < nCopies; p++ {
			proj := fmt.Sprintf("%s_%02d", projectNames[rng.Intn(len(projectNames))], p)
			dests = append(dests, filepath.Join(deptPath, proj))
		}
		if len(dests) >= nCopies {
			break
		}
	}
	return dests
}

// A path-and-scenario row is SubtreeEntry, declared in manifest.go with the
// rest of the on-disk schema. This file used to carry its own unexported copy;
// two identical types describing one JSON shape is how the two of them drift.

// departmentDirs returns the unique parent directories of the planned
// destinations, sorted, so scenario assignment is stable for a given plan.
func departmentDirs(dests []string) []string {
	seen := make(map[string]bool, len(dests))
	var out []string
	for _, d := range dests {
		p := filepath.Dir(d)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// planDestinationsDeep builds a 4-level layout: dept/region/team/project.
// Max ~500 entries at any level. 8 depts x 8 regions x 16 teams x ceil(N/1024) projects.
func planDestinationsDeep(targetRoot string, nCopies int, rng *rand.Rand) []string {
	depts := shuffled(deptNames, rng)
	regions := shuffled(regionNames, rng)
	teams := shuffled(teamNames, rng)

	slots := len(depts) * len(regions) * len(teams)
	projsPerSlot := max(1, (nCopies+slots-1)/slots)

	dests := make([]string, 0, nCopies)
	for _, dept := range depts {
		for _, region := range regions {
			for _, team := range teams {
				for p := 0; p < projsPerSlot && len(dests) < nCopies; p++ {
					proj := fmt.Sprintf("%s_%04d", projectNames[rng.Intn(len(projectNames))], p)
					parent := filepath.Join(targetRoot, dept, region, team)
					dests = append(dests, filepath.Join(parent, proj))
				}
				if len(dests) >= nCopies {
					return dests
				}
			}
		}
	}
	return dests
}

func shuffled(names []string, rng *rand.Rand) []string {
	out := make([]string, len(names))
	copy(out, names)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func FanOut(seedRoot, targetRoot string, nCopies, workers int, rng *rand.Rand) (int, error) {
	return FanOutContext(context.Background(), seedRoot, targetRoot, nCopies, workers, rng)
}

func FanOutContext(ctx context.Context, seedRoot, targetRoot string, nCopies, workers int, rng *rand.Rand) (int, error) {
	if err := os.MkdirAll(targetRoot, 0755); err != nil {
		return 0, err
	}

	entries, err := collectSeedPaths(seedRoot)
	if err != nil {
		return 0, fmt.Errorf("collecting seed paths: %w", err)
	}

	dests := planDestinations(targetRoot, nCopies, rng)
	for _, d := range dests {
		os.MkdirAll(filepath.Dir(d), 0755)
	}

	var done atomic.Int64
	total := len(dests)

	work := make(chan string, total)
	for _, d := range dests {
		work <- d
	}
	close(work)

	var wg sync.WaitGroup
	errs := make(chan error, total)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range work {
				if ctx.Err() != nil {
					return
				}
				if err := copyTreeCached(entries, d); err != nil {
					errs <- fmt.Errorf("copy to %s: %w", d, err)
					continue
				}
				n := done.Add(1)
				if n%50 == 0 || n == int64(total) {
					fmt.Fprintf(os.Stderr, "  %d/%d copies done\r", n, total)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		return int(done.Load()), err
	}
	if ctx.Err() != nil {
		return int(done.Load()), ctx.Err()
	}
	fmt.Fprintf(os.Stderr, "  %d/%d copies done\n", done.Load(), total)
	return int(done.Load()), nil
}

// FanOutAndStamp creates the tree and stamps ACLs in a single pass — no re-walk.
// Each worker creates files/dirs from the cached seed paths and immediately stamps
// the ACL, halving total NFS operations compared to separate FanOut + StampACLs.
func FanOutAndStamp(seedRoot, targetRoot string, nCopies, workers int, rng *rand.Rand,
	roleMap map[string]string, safetyPrincipal string, filesPerSubtree int, meta ManifestMeta) (*StampResult, error) {
	return FanOutAndStampContext(context.Background(), seedRoot, targetRoot, nCopies, workers, rng,
		roleMap, safetyPrincipal, filesPerSubtree, meta)
}

func FanOutAndStampContext(ctx context.Context, seedRoot, targetRoot string, nCopies, workers int, rng *rand.Rand,
	roleMap map[string]string, safetyPrincipal string, filesPerSubtree int, meta ManifestMeta) (*StampResult, error) {

	if err := os.MkdirAll(targetRoot, 0755); err != nil {
		return nil, err
	}

	entries, err := collectSeedPaths(seedRoot)
	if err != nil {
		return nil, fmt.Errorf("collecting seed paths: %w", err)
	}

	// Pre-encode all scenarios
	dirScenarios := DirScenarios()
	fileScenarios := FileScenarios()
	encodedDirScenarios := make([]preEncodedScenario, len(dirScenarios))
	for i, s := range dirScenarios {
		enc, err := preEncodeScenario(s, roleMap, safetyPrincipal)
		if err != nil {
			return nil, err
		}
		encodedDirScenarios[i] = enc
	}
	encodedFileScenarios := make([]preEncodedScenario, len(fileScenarios))
	for i, s := range fileScenarios {
		enc, err := preEncodeScenario(s, roleMap, safetyPrincipal)
		if err != nil {
			return nil, err
		}
		encodedFileScenarios[i] = enc
	}

	dests := planDestinations(targetRoot, nCopies, rng)
	deptDirs := departmentDirs(dests)
	for _, d := range deptDirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}

	type indexedDest struct {
		path string
		idx  int
	}

	total := len(dests)
	work := make(chan indexedDest, total)
	for i, d := range dests {
		work <- indexedDest{path: d, idx: i}
	}
	close(work)

	var done atomic.Int64
	var applied atomic.Int64
	var totalPaths atomic.Int64
	var failures atomic.Int64
	var scenarioCounts sync.Map

	// Per-worker outlier collection to avoid mutex contention
	type workerResult struct {
		outliers []FileOutlier
	}
	workerResults := make([]workerResult, workers)

	// Stamp the department directories. These are created outside the per-entry
	// loop, so without this they would be the only directories in the tree with
	// no scenario ACL — and they are the first paths a top-down repairer touches.
	// Scenario assignment is a deterministic index into the dir scenario table.
	stampOne := func(path string, enc *preEncodedScenario, isDir bool) {
		val, _ := scenarioCounts.LoadOrStore(enc.scenario.Name, &scenarioStats{})
		stats := val.(*scenarioStats)
		stats.total.Add(1)
		data := enc.fileData
		if isDir {
			data = enc.dirData
		}
		if err := nfs4acl.SetACL(path, data); err != nil {
			failures.Add(1)
		} else {
			stats.applied.Add(1)
			applied.Add(1)
		}
		totalPaths.Add(1)
	}
	deptEntries := make([]SubtreeEntry, len(deptDirs))
	for i, d := range deptDirs {
		enc := &encodedDirScenarios[i%len(encodedDirScenarios)]
		deptEntries[i] = SubtreeEntry{Path: d, Scenario: enc.scenario.Name}
		stampOne(d, enc, true)
	}

	var wg sync.WaitGroup
	errs := make(chan error, total)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for d := range work {
				if ctx.Err() != nil {
					return
				}
				enc := &encodedDirScenarios[d.idx%len(encodedDirScenarios)]
				subtreeRng := rand.New(rand.NewSource(int64(d.idx)))
				fileCount := 0

				// The subtree root is created implicitly by the entry loop, so
				// stamp and count it explicitly here.
				if err := os.MkdirAll(d.path, 0755); err != nil {
					errs <- fmt.Errorf("mkdir %s: %w", d.path, err)
					continue
				}
				stampOne(d.path, enc, true)

				for _, e := range entries {
					target := filepath.Join(d.path, e.RelPath)
					if e.IsDir {
						if err := os.MkdirAll(target, 0755); err != nil {
							errs <- fmt.Errorf("mkdir %s: %w", target, err)
							break
						}
						// Stamp dir ACL
						stampOne(target, enc, true)
					} else {
						fd, err := unix.Open(target, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0644)
						if err != nil {
							errs <- fmt.Errorf("create %s: %w", target, err)
							break
						}
						unix.Close(fd)
						// Stamp file ACL (inherits dir scenario)
						stampOne(target, enc, false)

						// Reservoir sample for file outliers
						fileCount++
						if filesPerSubtree > 0 && subtreeRng.Intn(fileCount) < filesPerSubtree {
							fenc := &encodedFileScenarios[(d.idx+fileCount)%len(encodedFileScenarios)]
							fval, _ := scenarioCounts.LoadOrStore(fenc.scenario.Name, &scenarioStats{})
							fstats := fval.(*scenarioStats)
							fstats.total.Add(1)
							if err := nfs4acl.SetACL(target, fenc.fileData); err != nil {
								failures.Add(1)
							} else {
								fstats.applied.Add(1)
								applied.Add(1)
							}
							// No totalPaths increment: this is a second stamp on
							// a path already counted above. applied/scenario
							// totals are the home for stamp-operation counts.
							workerResults[workerID].outliers = append(workerResults[workerID].outliers, FileOutlier{
								Path:     target,
								Scenario: fenc.scenario.Name,
							})
						}
					}
				}

				n := done.Add(1)
				a := applied.Load()
				if n%50 == 0 || n == int64(total) {
					fmt.Fprintf(os.Stderr, "  %d/%d subtrees, %d ACLs applied\r", n, total, a)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Merge per-worker outliers
	var allOutliers []FileOutlier
	for _, wr := range workerResults {
		allOutliers = append(allOutliers, wr.outliers...)
	}

	fmt.Fprintf(os.Stderr, "  %d/%d subtrees, %d ACLs applied\n", done.Load(), total, applied.Load())

	// Write compact manifest: one row per department and per subtree, plus file
	// outliers.
	subtreeEntries := make([]SubtreeEntry, len(dests))
	for i, d := range dests {
		subtreeEntries[i] = SubtreeEntry{
			Path:     d,
			Scenario: encodedDirScenarios[i%len(encodedDirScenarios)].scenario.Name,
		}
	}
	manifestPath := resolveManifestPath(meta.Path, targetRoot)
	meta.Path = recordedManifestPath(manifestPath, targetRoot)
	if err := writeManifestTo(manifestPath, buildManifest(targetRoot, meta,
		totalPaths.Load(), applied.Load(), failures.Load(), deptEntries, subtreeEntries, allOutliers)); err != nil {
		return nil, err
	}

	result := &StampResult{
		ManifestPath: manifestPath,
		TotalPaths:   totalPaths.Load(),
		Applied:      applied.Load(),
		Failures:     failures.Load(),
	}
	result.Scenarios = collectScenarioResult(&scenarioCounts)

	return result, nil
}

// BeastModeWorkers returns a worker count scaled to available CPUs.
func BeastModeWorkers() int {
	return runtime.NumCPU() * 3
}

// Phase 3: ACL stamping
//
// Performance-critical path. Key optimizations over the naive approach:
//   - Pre-encode ACL bytes per scenario (2 forms: dir, file). No per-path parsing.
//   - Pipeline: walk subtrees and stamp concurrently. No 100M job slice.
//   - Single walk per subtree (no double walk for file outliers).
//   - Parallel subtree walks — subtrees are independent.
//   - filepath.Walk visits parent before child — no sort needed.

type preEncodedScenario struct {
	scenario Scenario
	dirACEs  []string
	fileACEs []string
	dirData  []byte
	fileData []byte
}

func preEncodeScenario(s Scenario, roleMap map[string]string, safetyPrincipal string) (preEncodedScenario, error) {
	dirACEs := s.ACEs(roleMap)
	if safetyPrincipal != "" {
		dirACEs = append(dirACEs, ace("A", "fd", safetyPrincipal, MaskFull))
	}

	fileACEs := s.ACEs(roleMap)
	for i, a := range fileACEs {
		fileACEs[i] = stripInheritFlags(a)
	}
	if safetyPrincipal != "" {
		fileACEs = append(fileACEs, ace("A", "", safetyPrincipal, MaskFull))
	}

	dirParsed, err := parseACEs(dirACEs)
	if err != nil {
		return preEncodedScenario{}, fmt.Errorf("scenario %s dir: %w", s.Name, err)
	}
	fileParsed, err := parseACEs(fileACEs)
	if err != nil {
		return preEncodedScenario{}, fmt.Errorf("scenario %s file: %w", s.Name, err)
	}

	return preEncodedScenario{
		scenario: s,
		dirACEs:  dirACEs,
		fileACEs: fileACEs,
		dirData:  nfs4acl.Encode(dirParsed),
		fileData: nfs4acl.Encode(fileParsed),
	}, nil
}

type stampJob struct {
	path    string
	isDir   bool
	encoded *preEncodedScenario
}

type ScenarioResult struct {
	Name    string
	Total   int
	Applied int
}

type StampResult struct {
	ManifestPath string
	// TotalPaths is a count of distinct paths in the tree (dirs + files),
	// each counted exactly once. Stamp operations — which exceed the path
	// count because outlier files are stamped twice — live in Applied.
	TotalPaths int64
	Applied    int64
	Failures   int64
	Scenarios  []ScenarioResult
	Subtrees   []SubtreeEntry // populated by userspace path for manifest
}

func StampACLs(target string, roleMap map[string]string, safetyPrincipal string, filesPerSubtree, workers int, rng *rand.Rand, dryRun bool, meta ManifestMeta) (*StampResult, error) {
	return StampACLsContext(context.Background(), target, roleMap, safetyPrincipal, filesPerSubtree, workers, rng, dryRun, meta)
}

func StampACLsContext(ctx context.Context, target string, roleMap map[string]string, safetyPrincipal string, filesPerSubtree, workers int, rng *rand.Rand, dryRun bool, meta ManifestMeta) (*StampResult, error) {
	dirScenarios := DirScenarios()
	fileScenarios := FileScenarios()

	// Pre-encode all scenarios
	encodedDirScenarios := make([]preEncodedScenario, len(dirScenarios))
	for i, s := range dirScenarios {
		enc, err := preEncodeScenario(s, roleMap, safetyPrincipal)
		if err != nil {
			return nil, err
		}
		encodedDirScenarios[i] = enc
	}
	encodedFileScenarios := make([]preEncodedScenario, len(fileScenarios))
	for i, s := range fileScenarios {
		enc, err := preEncodeScenario(s, roleMap, safetyPrincipal)
		if err != nil {
			return nil, err
		}
		encodedFileScenarios[i] = enc
	}

	// Find subtree roots (project dirs = second level under target)
	var subtreeRoots []string
	var deptDirs []string
	depts, _ := os.ReadDir(target)
	for _, dept := range depts {
		if !dept.IsDir() {
			continue
		}
		deptPath := filepath.Join(target, dept.Name())
		projs, _ := os.ReadDir(deptPath)
		found := false
		for _, proj := range projs {
			if proj.IsDir() {
				subtreeRoots = append(subtreeRoots, filepath.Join(deptPath, proj.Name()))
				found = true
			}
		}
		if found {
			deptDirs = append(deptDirs, deptPath)
		}
	}
	sort.Strings(subtreeRoots)
	sort.Strings(deptDirs)

	if len(subtreeRoots) == 0 {
		return nil, fmt.Errorf("no project subtrees found under %s", target)
	}

	fmt.Fprintf(os.Stderr, "  %d subtrees, %d dir scenarios, %d file scenarios\n",
		len(subtreeRoots), len(dirScenarios), len(fileScenarios))

	if dryRun {
		dryRunEntries(subtreeRoots, encodedDirScenarios, encodedFileScenarios, filesPerSubtree)
		return &StampResult{TotalPaths: int64(len(subtreeRoots))}, nil
	}

	// Pipeline: walk subtrees in parallel, feed jobs to stamp workers.
	// Channel depth limits memory — at 100M files we don't want all jobs queued.
	jobs := make(chan stampJob, workers*100)
	var applied atomic.Int64
	var totalPaths atomic.Int64

	// Stamp workers — no per-path manifest (would be 74GB+ at 100M paths).
	// Compact manifest written at the end: subtree assignments + file outliers.
	var scenarioCounts sync.Map
	var failures atomic.Int64

	type stampBatch []stampJob
	batchChan := make(chan stampBatch, workers*2)

	var stampWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		stampWG.Add(1)
		go func() {
			defer stampWG.Done()
			for batch := range batchChan {
				for _, j := range batch {
					var data []byte
					if j.isDir {
						data = j.encoded.dirData
					} else {
						data = j.encoded.fileData
					}

					val, _ := scenarioCounts.LoadOrStore(j.encoded.scenario.Name, &scenarioStats{})
					stats := val.(*scenarioStats)
					stats.total.Add(1)

					if err := nfs4acl.SetACL(j.path, data); err != nil {
						failures.Add(1)
					} else {
						stats.applied.Add(1)
						n := applied.Add(1)
						if n%10000 == 0 {
							fmt.Fprintf(os.Stderr, "  %d ACLs applied\r", n)
						}
					}
				}
			}
		}()
	}

	// Adapter: collect jobs into batches of 64 before dispatching
	const batchSize = 64
	go func() {
		batch := make(stampBatch, 0, batchSize)
		for j := range jobs {
			batch = append(batch, j)
			if len(batch) >= batchSize {
				batchChan <- batch
				batch = make(stampBatch, 0, batchSize)
			}
		}
		if len(batch) > 0 {
			batchChan <- batch
		}
		close(batchChan)
	}()

	// Department directories sit above the subtree roots, so no subtree walk
	// reaches them. Stamp and count them explicitly, with a deterministic
	// scenario index so the manifest records the intent.
	deptEntries := make([]SubtreeEntry, len(deptDirs))
	for i, d := range deptDirs {
		enc := &encodedDirScenarios[i%len(encodedDirScenarios)]
		deptEntries[i] = SubtreeEntry{Path: d, Scenario: enc.scenario.Name}
		jobs <- stampJob{path: d, isDir: true, encoded: enc}
		totalPaths.Add(1)
	}

	// Walk subtrees in parallel, feeding the stamp channel.
	// Use a pool of walkers to avoid overwhelming NFS readdir.
	walkWorkers := workers
	if walkWorkers > 64 {
		walkWorkers = 64
	}
	subtreeWork := make(chan int, len(subtreeRoots))
	for i := range subtreeRoots {
		subtreeWork <- i
	}
	close(subtreeWork)

	// Track file outliers for compact manifest (path + scenario name only)
	var outlierMu sync.Mutex
	var fileOutliers []FileOutlier

	var walkWG sync.WaitGroup
	for i := 0; i < walkWorkers; i++ {
		walkWG.Add(1)
		go func() {
			defer walkWG.Done()
			for idx := range subtreeWork {
				if ctx.Err() != nil {
					return
				}
				root := subtreeRoots[idx]
				enc := &encodedDirScenarios[idx%len(encodedDirScenarios)]

				fileCount := 0
				subtreeRng := rand.New(rand.NewSource(int64(idx)))
				var fileOutlierTargets int
				if filesPerSubtree > 0 {
					fileOutlierTargets = filesPerSubtree
				}

				walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if info.IsDir() {
						jobs <- stampJob{path: path, isDir: true, encoded: enc}
						totalPaths.Add(1)
					} else {
						jobs <- stampJob{path: path, isDir: false, encoded: enc}
						totalPaths.Add(1)
						// Reservoir sample for file outliers
						fileCount++
						if fileOutlierTargets > 0 && subtreeRng.Intn(fileCount) < fileOutlierTargets {
							fenc := &encodedFileScenarios[(idx+fileCount)%len(encodedFileScenarios)]
							jobs <- stampJob{path: path, isDir: false, encoded: fenc}
							// No totalPaths increment: second stamp on a path
							// already counted above.
							outlierMu.Lock()
							fileOutliers = append(fileOutliers, FileOutlier{
								Path:     path,
								Scenario: fenc.scenario.Name,
							})
							outlierMu.Unlock()
						}
					}
					return nil
				})
				if walkErr != nil && ctx.Err() == nil {
					failures.Add(1)
				}
			}
		}()
	}
	walkWG.Wait()
	close(jobs)
	stampWG.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Write compact manifest: subtree assignments + file outliers.
	// O(subtrees + outliers), not O(files). ~50KB at huge scale, not 74GB.
	subtreeEntries := make([]SubtreeEntry, len(subtreeRoots))
	for i, root := range subtreeRoots {
		subtreeEntries[i] = SubtreeEntry{
			Path:     root,
			Scenario: encodedDirScenarios[i%len(encodedDirScenarios)].scenario.Name,
		}
	}
	manifestPath := resolveManifestPath(meta.Path, target)
	meta = recoverShape(meta, manifestPath)
	meta.Path = recordedManifestPath(manifestPath, target)
	if err := writeManifestTo(manifestPath, buildManifest(target, meta,
		totalPaths.Load(), applied.Load(), failures.Load(), deptEntries, subtreeEntries, fileOutliers)); err != nil {
		return nil, err
	}

	total := totalPaths.Load()
	fmt.Fprintf(os.Stderr, "  %d ACLs applied (%d paths)\n", applied.Load(), total)

	result := &StampResult{
		ManifestPath: manifestPath,
		TotalPaths:   total,
		Applied:      applied.Load(),
		Failures:     failures.Load(),
	}
	result.Scenarios = collectScenarioResult(&scenarioCounts)

	return result, nil
}

func dryRunEntries(subtreeRoots []string, dirScenarios, fileScenarios []preEncodedScenario, filesPerSubtree int) {
	scenarioSeen := map[string]bool{}
	for idx, root := range subtreeRoots {
		enc := dirScenarios[idx%len(dirScenarios)]
		if !scenarioSeen[enc.scenario.Name] {
			scenarioSeen[enc.scenario.Name] = true
			fmt.Fprintf(os.Stderr, "  %-30s %s\n", enc.scenario.Name, root)
		}
	}
	for i, fs := range fileScenarios {
		if !scenarioSeen[fs.scenario.Name] {
			scenarioSeen[fs.scenario.Name] = true
			fmt.Fprintf(os.Stderr, "  %-30s (file scenario %d)\n", fs.scenario.Name, i)
		}
	}
	fmt.Fprintf(os.Stderr, "  %d subtrees, %d scenarios\n", len(subtreeRoots), len(scenarioSeen))
}

func stripInheritFlags(aceStr string) string {
	parts := strings.SplitN(aceStr, ":", 4)
	if len(parts) != 4 {
		return aceStr
	}
	flags := parts[1]
	var clean []byte
	for _, ch := range []byte(flags) {
		if ch != 'f' && ch != 'd' && ch != 'n' && ch != 'i' {
			clean = append(clean, ch)
		}
	}
	parts[1] = string(clean)
	return strings.Join(parts, ":")
}

func parseACEs(aceStrings []string) ([]nfs4acl.ACE, error) {
	var out []nfs4acl.ACE
	for _, s := range aceStrings {
		a, err := nfs4acl.ParseACELine(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// Run executes the full generation pipeline.
func Run(cfg Config) error {
	return RunContext(context.Background(), cfg)
}

// RunContext is like Run but observes ctx for cancellation.
func RunContext(ctx context.Context, cfg Config) error {
	rng := rand.New(rand.NewSource(cfg.Seed))

	roleMap := buildRoleMap(cfg.Roster)

	safetyPrincipal, err := safetyPrincipalFor(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Safety principal: %s\n", safetyPrincipal)

	// Validate principals — only when re-stamping an existing tree (ACLsOnly),
	// because the full generation path validates after creating the target.
	if !cfg.DryRun && cfg.ACLsOnly {
		fmt.Fprintf(os.Stderr, "Validating principals against NFS server...\n")
		if err := ValidatePrincipals(cfg.Target, roleMap, safetyPrincipal); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "  All principals resolve.\n")
	}

	t0 := time.Now()

	if !cfg.ACLsOnly {
		if cfg.DryRun {
			fmt.Fprintf(os.Stderr, "[dry-run] would build tree at %s\n", cfg.Target)
			fmt.Fprintf(os.Stderr, "  scale: %d copies, %d seed files, max depth %d\n",
				cfg.Scale.Copies, cfg.Scale.SeedFiles, cfg.Scale.MaxDepth)
			return nil
		}

		if !cfg.NoACLs && cfg.Transport == "userspace" {
			return generateUserspace(cfg, rng, roleMap, safetyPrincipal, t0)
		}

		if err := generateKernel(ctx, cfg, rng, roleMap, safetyPrincipal, t0); err != nil {
			return err
		}
		// The ACL path reports its own result and is terminal; only the
		// --no-acls path falls through to the tail below.
		if !cfg.NoACLs {
			return nil
		}
	}

	if cfg.NoACLs {
		fmt.Fprintf(os.Stderr, "Skipping ACL stamping (--no-acls)\n")
		fmt.Fprintf(os.Stderr, "Total: %.1fs\n", time.Since(t0).Seconds())
		return nil
	}

	return stampExisting(ctx, cfg, rng, roleMap, safetyPrincipal, t0)
}

// generateUserspace builds and stamps a tree over the userspace NFS4.1
// transport: the seed is planned in memory, so no writable local mount is
// needed. It reports its own result.
func generateUserspace(cfg Config, rng *rand.Rand, roleMap map[string]string, safetyPrincipal string, t0 time.Time) error {
	fmt.Fprintf(os.Stderr, "Planning seed: %d files, max depth %d\n", cfg.Scale.SeedFiles, cfg.Scale.MaxDepth)
	entries, fileCount := planSeedEntries(cfg.Scale.SeedFiles, cfg.Scale.MaxDepth, rng)
	fmt.Fprintf(os.Stderr, "  Seed: %d entries planned (%d files)\n", len(entries), fileCount)
	t1 := time.Now()

	fmt.Fprintf(os.Stderr, "Connecting userspace transport to %s:%s (%d connections)\n",
		cfg.Server, cfg.Export, cfg.Connections)
	client, err := ConnectUserspace(cfg.Server, cfg.Export, cfg.Connections, cfg.Auth)
	if err != nil {
		return fmt.Errorf("userspace connect: %w", err)
	}
	defer client.Close()

	mounts, err := openMountTable()
	if err != nil {
		return fmt.Errorf("resolve export-relative path: %w", err)
	}
	var mountsReader io.Reader
	if mounts != nil {
		defer mounts.Close()
		mountsReader = mounts
	}
	exportRelTarget, mountNote, err := resolveExportRelTarget(cfg.Target, cfg.Export, mountsReader)
	if err != nil {
		return fmt.Errorf("resolve export-relative path: %w", err)
	}
	if mountNote != "" {
		fmt.Fprintln(os.Stderr, mountNote)
	}

	// The emptiness precheck goes over the wire on this path: there may
	// be no local view of the target at all. The os.ReadDir equivalent
	// in generateKernel guards only the kernel path.
	// Not reached on cfg.DryRun: a dry run printed its plan and returned
	// in RunContext, before the seed was even planned.
	empty, err := userspaceTargetIsEmpty(client, exportRelTarget)
	if err != nil {
		return fmt.Errorf("checking whether %s is empty: %w", cfg.Target, err)
	}
	if !empty {
		return fmt.Errorf("%s exists and is not empty (use --acls-only to re-stamp)", cfg.Target)
	}

	fmt.Fprintf(os.Stderr, "Fanning out %d copies via userspace (%d workers)\n", cfg.Scale.Copies, cfg.Workers)
	result, err := FanOutAndStampUserspace(client, entries, exportRelTarget,
		cfg.Scale.Copies, cfg.Workers, rng, roleMap, safetyPrincipal, cfg.FilesPerSubtree)
	if err != nil {
		return fmt.Errorf("userspace fan-out+stamp: %w", err)
	}

	writeUserspaceManifest(cfg, result, exportRelTarget, mountNote)
	return printResult(result, t0, t1)
}

// writeUserspaceManifest writes the manifest locally — the NFS4.1 client has
// no OP_WRITE. cfg.Target is a local directory only when the mount table
// explained it. resolveExportRelTarget returns a note exactly when it did not,
// so an empty note is the signal that a local path exists to put the manifest
// beside; anything else and cfg.Target names a directory on the server, which
// must never be joined onto the local filesystem (finding 12).
func writeUserspaceManifest(cfg Config, result *StampResult, exportRelTarget, mountNote string) {
	localTarget := cfg.Target
	if mountNote != "" {
		localTarget = ""
	}
	mpath := resolveManifestPath(cfg.ManifestPath, localTarget)

	meta := ManifestMeta{
		Roster: cfg.Roster,
		Shape:  ShapeFromConfig(cfg),
		Path:   recordedManifestPath(mpath, localTarget),
	}
	manifest := buildManifest("/"+exportRelTarget, meta,
		result.TotalPaths, result.Applied, result.Failures,
		nil, result.Subtrees, nil)
	if err := writeManifestTo(mpath, manifest); err != nil {
		fmt.Fprintf(os.Stderr, "  WARNING: failed to write manifest: %v\n", err)
	} else {
		result.ManifestPath = mpath
	}
}

// generateKernel builds the seed on disk and fans it out over the kernel
// mount. With ACLs it stamps in the same pass and reports its own result;
// with --no-acls it prints fan-out timings and returns for the caller to
// finish.
func generateKernel(ctx context.Context, cfg Config, rng *rand.Rand, roleMap map[string]string, safetyPrincipal string, t0 time.Time) error {
	entries, err := os.ReadDir(cfg.Target)
	if err == nil && len(entries) > 0 {
		return fmt.Errorf("%s exists and is not empty (use --acls-only to re-stamp)", cfg.Target)
	}

	if !cfg.NoACLs {
		if err := ensureSafetyRoot(cfg.Target, safetyPrincipal); err != nil {
			return err
		}
	}

	// Phase 1: Build seed on disk (kernel transport)
	seedDir := filepath.Join(cfg.Target, ".seed")
	fmt.Fprintf(os.Stderr, "Building seed tree: %d files, max depth %d\n", cfg.Scale.SeedFiles, cfg.Scale.MaxDepth)
	seedCount, err := BuildSeedContext(ctx, seedDir, cfg.Scale.SeedFiles, cfg.Scale.MaxDepth, rng)
	if err != nil {
		return fmt.Errorf("seed build: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  Seed: %d files created\n", seedCount)
	t1 := time.Now()

	if !cfg.NoACLs {
		// Validate principals before fan-out so we fail fast
		fmt.Fprintf(os.Stderr, "Validating principals against NFS server...\n")
		if err := ValidatePrincipals(cfg.Target, roleMap, safetyPrincipal); err != nil {
			os.RemoveAll(seedDir)
			return err
		}
		fmt.Fprintf(os.Stderr, "  All principals resolve.\n")

		// Fused: create files + stamp ACLs in one pass
		fmt.Fprintf(os.Stderr, "Fanning out %d copies + stamping ACLs (%d workers)\n", cfg.Scale.Copies, cfg.Workers)
		result, err := FanOutAndStampContext(ctx, seedDir, cfg.Target, cfg.Scale.Copies, cfg.Workers, rng,
			roleMap, safetyPrincipal, cfg.FilesPerSubtree,
			ManifestMeta{Roster: cfg.Roster, Shape: ShapeFromConfig(cfg), Path: cfg.ManifestPath})
		os.RemoveAll(seedDir)
		if err != nil {
			return fmt.Errorf("fan-out+stamp: %w", err)
		}
		return printResult(result, t0, t1)
	}

	// --no-acls: fan-out only
	fmt.Fprintf(os.Stderr, "Fanning out %d copies (%d workers)\n", cfg.Scale.Copies, cfg.Workers)
	copies, err := FanOutContext(ctx, seedDir, cfg.Target, cfg.Scale.Copies, cfg.Workers, rng)
	// Removed before the error check, as the ACL path does: a failed
	// fan-out is exactly when a stale seed is most confusing, because the
	// operator's next move is to look at what is on disk.
	os.RemoveAll(seedDir)
	if err != nil {
		return fmt.Errorf("fan-out: %w", err)
	}
	t2 := time.Now()
	fmt.Fprintf(os.Stderr, "  ~%d files across %d subtrees\n", seedCount*copies, copies)
	fmt.Fprintf(os.Stderr, "  Seed build: %.1fs\n", t1.Sub(t0).Seconds())
	fmt.Fprintf(os.Stderr, "  Fan-out:    %.1fs\n", t2.Sub(t1).Seconds())
	return nil
}

// ensureSafetyRoot creates the target and puts an inheritable allow ACE for
// the safety principal in front of whatever ACL it already has. Without it a
// share whose root carries only inherited ACEs for other principals gives the
// seed directory a mode of ---------, and the generator cannot write into the
// tree it is building. A target on a filesystem with no NFSv4 ACL is left
// alone; any other failure to read the ACL is returned rather than skipped,
// because skipping it is what leaves the seed build to fail with a bare
// permission error. An ACL that already holds the ACE is not rewritten, so a
// rerun against the same target does not grow it.
func ensureSafetyRoot(target, safetyPrincipal string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return fmt.Errorf("create target: %w", err)
	}
	raw, err := nfs4acl.GetACL(target)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTTY) {
			return nil
		}
		return fmt.Errorf("read ACL of %s: %w", target, err)
	}
	existing, err := nfs4acl.DecodeACL(raw)
	if err != nil {
		return fmt.Errorf("decode ACL of %s: %w", target, err)
	}
	safety, err := parseACEs([]string{ace("A", "fd", safetyPrincipal, MaskFull)})
	if err != nil {
		return err
	}
	aces, changed := withSafetyACE(existing, safety[0])
	if !changed {
		return nil
	}
	if err := nfs4acl.SetACL(target, nfs4acl.Encode(aces)); err != nil {
		return fmt.Errorf("set safety ACE on %s: %w", target, err)
	}
	return nil
}

// withSafetyACE returns existing with safety in front, and false when an
// identical ACE is already present. It is in front so the principal's access
// is evaluated before any deny that follows.
func withSafetyACE(existing []nfs4acl.ACE, safety nfs4acl.ACE) ([]nfs4acl.ACE, bool) {
	for _, a := range existing {
		if a.Type == safety.Type && a.Flags == safety.Flags && a.Mask == safety.Mask &&
			strings.EqualFold(a.Who, safety.Who) {
			return existing, false
		}
	}
	return append([]nfs4acl.ACE{safety}, existing...), true
}

// stampExisting is the --acls-only path: a standalone ACL stamp over a tree
// that already exists.
func stampExisting(ctx context.Context, cfg Config, rng *rand.Rand, roleMap map[string]string, safetyPrincipal string, t0 time.Time) error {
	fmt.Fprintf(os.Stderr, "Stamping ACLs\n")
	t3 := time.Now()
	// No shape is asserted here: a re-stamp did not create the tree, so this
	// run's Scale flags are not evidence of its shape. StampACLsContext keeps
	// whatever shape the existing manifest already records.
	result, err := StampACLsContext(ctx, cfg.Target, roleMap, safetyPrincipal, cfg.FilesPerSubtree, cfg.Workers, rng, cfg.DryRun,
		ManifestMeta{Roster: cfg.Roster, Path: cfg.ManifestPath})
	if err != nil {
		return fmt.Errorf("ACL stamp: %w", err)
	}
	t4 := time.Now()

	if !cfg.DryRun {
		elapsed := t4.Sub(t3).Seconds()
		rate := float64(result.TotalPaths) / max(elapsed, 0.001)
		fmt.Fprintf(os.Stderr, "  ACL stamp: %.1fs (%.0f paths/s)\n", elapsed, rate)

		if result.Failures > 0 {
			fmt.Fprintf(os.Stderr, "  WARNING: %d/%d paths failed\n", result.Failures, result.TotalPaths)
		}

		fmt.Fprintf(os.Stderr, "Manifest: %s\n", result.ManifestPath)
		fmt.Fprintf(os.Stderr, "Total: %.1fs\n", time.Since(t0).Seconds())
	}

	// Scenario summary
	fmt.Fprintf(os.Stderr, "\nScenario coverage:\n")
	fmt.Fprintf(os.Stderr, "  %-30s %7s %8s\n", "scenario", "paths", "applied")
	for _, s := range result.Scenarios {
		fmt.Fprintf(os.Stderr, "  %-30s %7d %8d\n", s.Name, s.Total, s.Applied)
	}

	return nil
}

func printResult(result *StampResult, t0, t1 time.Time) error {
	t2 := time.Now()
	elapsed := t2.Sub(t1).Seconds()
	rate := float64(result.TotalPaths) / max(elapsed, 0.001)
	fmt.Fprintf(os.Stderr, "  Seed build: %.1fs\n", t1.Sub(t0).Seconds())
	fmt.Fprintf(os.Stderr, "  Fan-out+stamp: %.1fs (%.0f paths/s)\n", elapsed, rate)
	if result.Failures > 0 {
		fmt.Fprintf(os.Stderr, "  WARNING: %d/%d paths failed\n", result.Failures, result.TotalPaths)
	}
	if result.ManifestPath != "" {
		fmt.Fprintf(os.Stderr, "Manifest: %s\n", result.ManifestPath)
	}
	fmt.Fprintf(os.Stderr, "Total: %.1fs\n", time.Since(t0).Seconds())
	fmt.Fprintf(os.Stderr, "\nScenario coverage:\n")
	fmt.Fprintf(os.Stderr, "  %-30s %7s %8s\n", "scenario", "paths", "applied")
	for _, s := range result.Scenarios {
		fmt.Fprintf(os.Stderr, "  %-30s %7d %8d\n", s.Name, s.Total, s.Applied)
	}
	return nil
}
