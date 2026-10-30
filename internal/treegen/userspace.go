package treegen

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// FanOutAndStampUserspace creates the tree and stamps ACLs entirely through the
// userspace NFSv4.1 transport — one RPC per file (OPEN+GETFH+CLOSE with ACL in
// createattrs), one RPC per directory (CREATE+GETFH with ACL in createattrs).
//
// The seed entries define the per-subtree structure (collected from the kernel-
// built seed tree). Each destination subtree is independent: its root dir FH is
// threaded down to children, so no LOOKUPs are needed.
func FanOutAndStampUserspace(
	client *nfs41.Client,
	seedEntries []seedEntry,
	exportRelTarget string,
	nCopies, workers int,
	rng *rand.Rand,
	roleMap map[string]string,
	safetyPrincipal string,
	filesPerSubtree int,
) (*StampResult, error) {

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

	root, err := client.Root()
	if err != nil {
		return nil, fmt.Errorf("userspace root: %w", err)
	}

	var safetyACL []byte
	var safetyACE nfs4acl.ACE
	if safetyPrincipal != "" {
		parsed, err := parseACEs([]string{ace("A", "fd", safetyPrincipal, MaskFull)})
		if err != nil {
			return nil, err
		}
		safetyACE = parsed[0]
		safetyACL = nfs4acl.Encode(parsed)
	}

	targetRef, err := resolveOrCreatePath(client, root, exportRelTarget, safetyACL)
	if err == nil && safetyPrincipal != "" {
		err = ensureSafetyACE(client, targetRef, safetyACE)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve target %s: %w", exportRelTarget, err)
	}

	dests := planDestinations("/"+exportRelTarget, nCopies, rng)

	// Pre-create all destination directories and cache their Refs.
	// This avoids per-worker ReadDir races on shared parent dirs.
	type indexedDest struct {
		ref transport.Ref
		idx int
	}
	total := len(dests)
	dirCache := &sync.Map{}
	dirCache.Store("", targetRef)

	fmt.Fprintf(os.Stderr, "  Creating %d destination directories...\n", total)
	destRefs := make([]transport.Ref, total)
	for i, d := range dests {
		rel := strings.TrimPrefix(strings.TrimPrefix(d, "/"), exportRelTarget+"/")
		ref, err := resolveOrCreateCached(client, targetRef, rel, dirCache)
		if err != nil {
			return nil, fmt.Errorf("create destination %s: %w", d, err)
		}
		destRefs[i] = ref
	}
	fmt.Fprintf(os.Stderr, "  Destination directories ready\n")

	work := make(chan indexedDest, total)
	for i := range dests {
		work <- indexedDest{ref: destRefs[i], idx: i}
	}
	close(work)

	var done atomic.Int64
	var applied atomic.Int64
	var totalPaths atomic.Int64
	var failures atomic.Int64
	var scenarioCounts sync.Map

	// No per-worker error slot: every failure here is a per-object one that is
	// counted in failures and reported in the result, not a reason to abandon
	// the fan-out. A slice that is allocated and read but never written reads
	// like errors are collected when they are not.
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for d := range work {
				enc := &encodedDirScenarios[d.idx%len(encodedDirScenarios)]
				subtreeRng := rand.New(rand.NewSource(int64(d.idx)))
				fileCount := 0

				destRef := d.ref
				dirRefs := map[string]transport.Ref{".": destRef}

				for _, e := range seedEntries {
					if e.IsDir {
						parentRel := path.Dir(e.RelPath)
						parentRef, ok := dirRefs[parentRel]
						if !ok {
							parentRef = destRef
						}

						dirName := path.Base(e.RelPath)
						childRef, err := client.Mkdir(parentRef, dirName, enc.dirData, 0755)
						if err != nil {
							failures.Add(1)
							continue
						}
						dirRefs[e.RelPath] = childRef

						val, _ := scenarioCounts.LoadOrStore(enc.scenario.Name, &scenarioStats{})
						stats := val.(*scenarioStats)
						stats.total.Add(1)
						stats.applied.Add(1)
						applied.Add(1)
						totalPaths.Add(1)
					} else {
						parentRel := path.Dir(e.RelPath)
						parentRef, ok := dirRefs[parentRel]
						if !ok {
							parentRef = destRef
						}

						fileName := path.Base(e.RelPath)
						fileRef, err := client.CreateFile(parentRef, fileName, enc.fileData, 0644)
						if err != nil {
							failures.Add(1)
							continue
						}

						val, _ := scenarioCounts.LoadOrStore(enc.scenario.Name, &scenarioStats{})
						stats := val.(*scenarioStats)
						stats.total.Add(1)
						stats.applied.Add(1)
						applied.Add(1)
						totalPaths.Add(1)

						fileCount++
						if filesPerSubtree > 0 && subtreeRng.Intn(fileCount) < filesPerSubtree {
							fenc := &encodedFileScenarios[(d.idx+fileCount)%len(encodedFileScenarios)]
							fval, _ := scenarioCounts.LoadOrStore(fenc.scenario.Name, &scenarioStats{})
							fstats := fval.(*scenarioStats)
							fstats.total.Add(1)
							if err := client.SetACL(fileRef, fenc.fileData); err != nil {
								failures.Add(1)
							} else {
								fstats.applied.Add(1)
								applied.Add(1)
								totalPaths.Add(1)

							}
						}
					}
				}

				n := done.Add(1)
				a := applied.Load()
				if n%50 == 0 || n == int64(total) {
					fmt.Fprintf(os.Stderr, "  %d/%d subtrees, %d created+stamped\r", n, total, a)
				}
			}
		}(w)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "  %d/%d subtrees, %d created+stamped\n", done.Load(), total, applied.Load())

	subtreeEntries := make([]SubtreeEntry, len(dests))
	for i, d := range dests {
		subtreeEntries[i] = SubtreeEntry{
			Path:     d,
			Scenario: encodedDirScenarios[i%len(encodedDirScenarios)].scenario.Name,
		}
	}

	result := &StampResult{
		TotalPaths: totalPaths.Load(),
		Applied:    applied.Load(),
		Failures:   failures.Load(),
		Subtrees:   subtreeEntries,
		Scenarios:  collectScenarioResult(&scenarioCounts),
	}

	fmt.Fprintf(os.Stderr, "  %d subtrees, %d scenarios\n", len(subtreeEntries), len(result.Scenarios))

	return result, nil
}

// pathClient is the slice of *nfs41.Client that resolveOrCreatePath needs, so
// the target setup can be tested without a server.
type pathClient interface {
	dirLister
	Mkdir(dirRef transport.Ref, name string, acl []byte, mode uint32) (transport.Ref, error)
	GetACL(ref transport.Ref) ([]byte, error)
	SetACL(ref transport.Ref, acl []byte) error
}

// resolveOrCreatePath resolves or creates a chain of directories from base.
// Tries Mkdir first (fast path for new trees). On EXIST, falls back to ReadDir
// to get the FH. On ACCESS (can't create in parent), falls back to ReadDir
// to find an existing dir.
//
// acl is set on every directory the chain creates. Without it a directory made
// under an export root that only passes down someone else's ACE has no owner
// access and mode ---------, and the next Mkdir inside it fails with ACCESS.
func resolveOrCreatePath(client pathClient, base transport.Ref, relPath string, acl []byte) (transport.Ref, error) {
	if relPath == "" || relPath == "." {
		return base, nil
	}
	parts := strings.Split(path.Clean(relPath), "/")
	current := base
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		childRef, err := client.Mkdir(current, part, acl, 0755)
		if err != nil {
			if nfs41.IsExist(err) || nfs41.IsAccess(err) {
				// The Mkdir error below is returned either way, and it
				// names the operation that actually failed; a READDIR
				// error here only says the fallback could not run.
				if ref, ok, _ := lookupChild(client, current, part); ok {
					current = ref
					continue
				}
			}
			return transport.Ref{}, err
		}
		current = childRef
	}
	return current, nil
}

// ensureSafetyACE puts safety in front of ref's ACL unless an identical ACE is
// already there. It is what resolveOrCreatePath's acl cannot do for a target
// that already existed: the userspace counterpart of ensureSafetyRoot.
func ensureSafetyACE(client pathClient, ref transport.Ref, safety nfs4acl.ACE) error {
	raw, err := client.GetACL(ref)
	if err != nil {
		return fmt.Errorf("read ACL of %s: %w", ref.Path, err)
	}
	existing, err := nfs4acl.DecodeACL(raw)
	if err != nil {
		return fmt.Errorf("decode ACL of %s: %w", ref.Path, err)
	}
	aces, changed := withSafetyACE(existing, safety)
	if !changed {
		return nil
	}
	if err := client.SetACL(ref, nfs4acl.Encode(aces)); err != nil {
		return fmt.Errorf("set safety ACE on %s: %w", ref.Path, err)
	}
	return nil
}

// resolveOrCreateCached is like resolveOrCreatePath but caches intermediate
// dir Refs in a sync.Map so repeated paths (shared parent dirs across
// destinations) hit at most one Mkdir.
func resolveOrCreateCached(client *nfs41.Client, base transport.Ref, relPath string, cache *sync.Map) (transport.Ref, error) {
	if relPath == "" || relPath == "." {
		return base, nil
	}
	parts := strings.Split(path.Clean(relPath), "/")
	prefix := ""
	current := base
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if prefix == "" {
			prefix = part
		} else {
			prefix = prefix + "/" + part
		}
		if cached, ok := cache.Load(prefix); ok {
			current = cached.(transport.Ref)
			continue
		}
		childRef, err := client.Mkdir(current, part, nil, 0755)
		if err != nil {
			if nfs41.IsExist(err) || nfs41.IsAccess(err) {
				if ref, ok, _ := lookupChild(client, current, part); ok {
					cache.Store(prefix, ref)
					current = ref
					continue
				}
			}
			return transport.Ref{}, err
		}
		cache.Store(prefix, childRef)
		current = childRef
	}
	return current, nil
}

// dirLister is the slice of *nfs41.Client that directory traversal needs. It
// exists so the target-emptiness precheck can be tested without a server: the
// nfs41 package's fake lives in a _test.go file in package nfs41 and cannot be
// imported from here.
type dirLister interface {
	Root() (transport.Ref, error)
	ReadDir(ref transport.Ref) ([]transport.Dirent, error)
}

// userspaceTargetIsEmpty reports whether the export-relative target holds
// nothing, using READDIR over the wire rather than os.ReadDir.
//
// A target that does not exist counts as empty: the fan-out creates it, and the
// local precheck behaves the same way -- it ignores its error and refuses only
// on a successful read of a populated directory.
//
// The guard is worth having rather than dropping along with the mount:
// generating a million-object tree into a directory that already holds one
// interleaves two trees and leaves neither usable. Until now the userspace path
// had no such guard at all -- the os.ReadDir precheck in RunContext sits after
// the userspace branch has already returned, so it only ever protected the
// kernel path.
//
// len(entries) == 0 is the right test unfiltered: Client.ReadDir drops "." and
// ".." during decode, which internal/nfs41's TestReadDirSkipsDotAndDotDot
// pins. Filtering them again here would hide a real entry whose name starts
// with a dot.
func userspaceTargetIsEmpty(client dirLister, exportRelTarget string) (bool, error) {
	ref, err := client.Root()
	if err != nil {
		return false, fmt.Errorf("resolving export root: %w", err)
	}

	// path.Clean and a "/" split, not filepath: this is a server-side NFS path
	// and stays forward-slashed regardless of the client's OS.
	cleaned := strings.Trim(path.Clean("/"+exportRelTarget), "/")
	if cleaned != "" && cleaned != "." {
		for _, name := range strings.Split(cleaned, "/") {
			child, ok, err := lookupChild(client, ref, name)
			if err != nil {
				return false, fmt.Errorf("READDIR %s: %w", ref.Path, err)
			}
			if !ok {
				return true, nil // does not exist yet; the fan-out will create it
			}
			ref = child
		}
	}

	entries, err := client.ReadDir(ref)
	if err != nil {
		return false, fmt.Errorf("READDIR %s: %w", exportRelTarget, err)
	}
	return len(entries) == 0, nil
}

// lookupChild finds a child directory by name. The bool is "found"; the error
// is "the lookup could not be performed". They are separate returns because
// collapsing them is a safety bug: a caller deciding whether a directory is
// empty must not read a failed READDIR as "nothing is there".
func lookupChild(client dirLister, parent transport.Ref, name string) (transport.Ref, bool, error) {
	entries, err := client.ReadDir(parent)
	if err != nil {
		return transport.Ref{}, false, err
	}
	for _, e := range entries {
		if e.Name == name && e.IsDir {
			return e.Ref, true, nil
		}
	}
	return transport.Ref{}, false, nil
}

// ConnectUserspace creates an nfs41 client for generate-tree.
//
// auth is the AUTH_SYS credential every call will carry. Nil keeps nfs41's
// existing behaviour of building one from the running process, which is what a
// Linux run against an export that trusts local uids has always done.
func ConnectUserspace(server, export string, connections int, auth *nfs41.AuthSys) (*nfs41.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return nfs41.New(ctx, nfs41.Config{
		Auth:        auth,
		Server:      server,
		Export:      export,
		Connections: connections,
		RPCTimeout:  30 * time.Second,
		Log:         func(s string) { fmt.Fprintf(os.Stderr, "nfs41: %s\n", s) },
	})
}
