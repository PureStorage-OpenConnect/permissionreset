package nfs41

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/walk"
)

// differentialTree is the shape both transports repair. Directories and files
// are mixed at several depths because the spec's rules dispatch on type, and a
// tree of one kind would let a transport that ignores the distinction pass.
var differentialTree = []string{
	"a/b/c",
	"a/d",
	"e",
}

var differentialFiles = []string{
	"top.txt",
	"a/f1.txt",
	"a/b/f2.txt",
	"a/b/c/f3.sh",
	"a/d/f4.txt",
	"e/f5.dat",
}

// The sentinel is deliberately NOT the spec's ACL, and deliberately not a
// mode-derived default either: the point is that every object must be observed
// to MOVE. A run that writes nothing would leave these in place, which is the
// exact failure mode that was misdiagnosed as "Defect 2" on 2026-08-21 when no
// before-capture was taken.
var (
	sentinelDirACL = []string{
		"A:fd:OWNER@:rwaDxtTcCoy",
		"A:fdg:GROUP@:rwaDxtTcCoy",
		"A:fd:EVERYONE@:rxtncy",
	}
	sentinelFileACL = []string{
		"A::OWNER@:rwaTcCoy",
		"A:g:GROUP@:rncy",
		"A::EVERYONE@:rncy",
	}
)

const differentialSpec = `protocol: nfsv4
default:
  acl:
    - "A::OWNER@:rwaxtTcCoy"
    - "A:g:GROUP@:rxtncy"
    - "A::EVERYONE@:tcy"
rules:
  - match:
      type: directory
    acl:
      - "A:fd:OWNER@:rwaDxtTcCoy"
      - "A:fdg:GROUP@:rxtncy"
      - "A:fd:EVERYONE@:tcy"
  - match:
      type: file
      pattern: "*.sh"
    acl:
      - "A::OWNER@:rwaxtTcCoy"
      - "A:g:GROUP@:rxtncy"
      - "A::EVERYONE@:rxtncy"
  - match:
      type: file
    acl:
      - "A::OWNER@:rwaxtTcCoy"
      - "A:g:GROUP@:rxtncy"
      - "A::EVERYONE@:tcy"
`

// TestDifferentialAgainstTheArray applies the same spec through both transports
// and compares the resulting ACLs byte-for-byte, read back through the kernel
// mount so neither transport grades its own homework.
//
// Set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT, PERMISSIONRESET_TEST_MOUNT and
// PERMISSIONRESET_TEST_READBACK to run it. It is skipped otherwise, including in CI,
// because it needs an array.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.54:2049 \
//	PERMISSIONRESET_TEST_EXPORT=/bench-perms \
//	PERMISSIONRESET_TEST_MOUNT=/mnt/bench-perms \
//	PERMISSIONRESET_TEST_READBACK=/mnt/bench-perms-readback \
//	  go test ./internal/nfs41/ -run TestDifferential -v
//
// Reading each tree back with the transport that wrote it would pass even if the
// encoder and the decoder were wrong in the same direction, which is exactly the
// failure a positional fattr4 unpack invites. Hence the third reader.
//
// PERMISSIONRESET_TEST_READBACK must be a SEPARATE mount of the same export with
// attribute caching off:
//
//	mount -t nfs4 -o vers=4.1,actimeo=0,nosharecache SERVER:EXPORT /mnt/...-readback
//
// This is not belt-and-braces. MEASURED 2026-08-21: reading back through
// PERMISSIONRESET_TEST_MOUNT reported seven of ten objects still carrying the
// sentinel after a userspace run that had in fact written every one of them
// correctly. The userspace client writes straight to the server, so that
// superblock never learns its cached ACLs are stale, and the whole test finishes
// well inside acregmin/acdirmin — the before-capture in stage 1b is itself what
// primes the cache that then lies. An independent superblock with actimeo=0 is
// the only reader that answers from the server every time.
func TestDifferentialAgainstTheArray(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	mount := os.Getenv("PERMISSIONRESET_TEST_MOUNT")
	readback := os.Getenv("PERMISSIONRESET_TEST_READBACK")
	if server == "" || export == "" || mount == "" || readback == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT, PERMISSIONRESET_TEST_MOUNT and PERMISSIONRESET_TEST_READBACK")
	}
	if readback == mount {
		t.Fatal("PERMISSIONRESET_TEST_READBACK must be a different mount from PERMISSIONRESET_TEST_MOUNT; " +
			"reading back through the superblock that wrote the sentinel reports stale ACLs and " +
			"makes a correct userspace run look like a no-op")
	}

	// spec.Load takes a path, and both transports must be driven by the SAME
	// loaded spec: a second Load of the same text would still be a second object,
	// and a difference in the ACLs would no longer be attributable to a transport.
	specPath := filepath.Join(t.TempDir(), "differential.yaml")
	if err := os.WriteFile(specPath, []byte(differentialSpec), 0o644); err != nil {
		t.Fatalf("write the differential spec: %v", err)
	}
	sp, err := spec.Load(specPath)
	if err != nil {
		t.Fatalf("load the differential spec %s: %v", specPath, err)
	}

	const kernelDir, userspaceDir = "diff-kernel", "diff-userspace"
	kernelRoot := filepath.Join(mount, kernelDir)
	userspaceRoot := filepath.Join(mount, userspaceDir)
	// Every ACL read goes through the read-back mount, including the
	// before-capture: writing and reading on one superblock is what produced a
	// false failure, so no read in this test uses the mount that did the writing.
	kernelReadback := filepath.Join(readback, kernelDir)
	userspaceReadback := filepath.Join(readback, userspaceDir)

	// Stage 1: two identical trees, both stamped with the sentinel.
	for _, root := range []string{kernelRoot, userspaceRoot} {
		if err := os.RemoveAll(root); err != nil {
			t.Fatalf("clear %s: %v", root, err)
		}
		if err := buildDifferentialTree(root); err != nil {
			t.Fatalf("build %s: %v", root, err)
		}
	}

	// Stage 1b: assert the sentinel IS in place before anything repairs it. This
	// is the before-capture whose absence made a working run look broken.
	sentinelDirBytes := mustParseACL(t, sentinelDirACL)
	sentinelFileBytes := mustParseACL(t, sentinelFileACL)
	for _, rel := range append(append([]string{"."}, differentialTree...), differentialFiles...) {
		want := sentinelDirBytes
		if isDifferentialFile(rel) {
			want = sentinelFileBytes
		}
		for _, root := range []string{kernelReadback, userspaceReadback} {
			got, err := nfs4acl.GetACL(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("read the sentinel back from %s/%s: %v", root, rel, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/%s does not carry the sentinel before the run; the test cannot "+
					"tell a successful repair from a no-op", root, rel)
			}
		}
	}

	// Stage 2: repair the first tree through the kernel transport.
	kernelTransport, err := transport.NewKernel(kernelRoot)
	if err != nil {
		t.Fatalf("kernel transport: %v", err)
	}
	defer kernelTransport.Close()
	if err := repairTree(kernelTransport, transport.Ref{Path: kernelRoot}, sp); err != nil {
		t.Fatalf("kernel repair: %v", err)
	}

	// Stage 3: repair the second tree through the userspace transport, addressed
	// by its SERVER-side path. This is also the regression guard for Defect 1:
	// the target is below the export root, which could not be resolved at all
	// before e051870.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	serverTarget := export + "/" + userspaceDir
	userspaceTransport, err := New(ctx, Config{
		Server: server, Export: export, Target: serverTarget,
		Connections: 4, RPCTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("userspace transport for %s: %v", serverTarget, err)
	}
	defer userspaceTransport.Close()
	// Root() rather than a hand-built Ref: it carries the filehandle Init already
	// resolved, which is what production passes, and it fails loudly here if the
	// target below the export root did not resolve at all.
	userspaceRootRef, err := userspaceTransport.Root()
	if err != nil {
		t.Fatalf("userspace root for %s: %v", serverTarget, err)
	}
	if err := repairTree(userspaceTransport, userspaceRootRef, sp); err != nil {
		t.Fatalf("userspace repair: %v", err)
	}

	// Stage 4 and 5: read both back through the cache-free mount and compare.
	var compared int
	for _, rel := range append(append([]string{"."}, differentialTree...), differentialFiles...) {
		kernelACL, err := nfs4acl.GetACL(filepath.Join(kernelReadback, rel))
		if err != nil {
			t.Errorf("read %s/%s: %v", kernelDir, rel, err)
			continue
		}
		userspaceACL, err := nfs4acl.GetACL(filepath.Join(userspaceReadback, rel))
		if err != nil {
			t.Errorf("read %s/%s: %v", userspaceDir, rel, err)
			continue
		}
		if !bytes.Equal(kernelACL, userspaceACL) {
			t.Errorf("%s: the two transports produced different ACLs\n kernel:    %x\n userspace: %x",
				rel, kernelACL, userspaceACL)
			continue
		}
		// Equal is not enough: both could have written nothing. Every object must
		// also have moved off the sentinel.
		sentinel := sentinelDirBytes
		if isDifferentialFile(rel) {
			sentinel = sentinelFileBytes
		}
		if bytes.Equal(kernelACL, sentinel) {
			t.Errorf("%s: both transports agree, but the ACL is still the sentinel — "+
				"neither run wrote anything", rel)
			continue
		}
		compared++
	}

	want := 1 + len(differentialTree) + len(differentialFiles)
	if compared != want {
		t.Errorf("compared %d of %d objects; every object must be checked or a transport "+
			"could skip a whole class of them silently", compared, want)
	}
	t.Logf("both transports agree, and every object moved off the sentinel, across %d objects",
		compared)
}

func isDifferentialFile(rel string) bool {
	for _, f := range differentialFiles {
		if f == rel {
			return true
		}
	}
	return false
}

func mustParseACL(t *testing.T, lines []string) []byte {
	t.Helper()
	data, err := nfs4acl.ParseACLSpec(lines)
	if err != nil {
		t.Fatalf("parse %v: %v", lines, err)
	}
	return data
}

// buildDifferentialTree creates the tree and stamps every object with the
// sentinel ACL. The sentinel goes on with nfs4acl.SetACL through the mount, so
// the userspace transport plays no part in setting up its own input.
func buildDifferentialTree(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for _, dir := range differentialTree {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return err
		}
	}
	for _, file := range differentialFiles {
		if err := os.WriteFile(filepath.Join(root, file), []byte("differential\n"), 0o644); err != nil {
			return err
		}
	}

	dirACL, err := nfs4acl.ParseACLSpec(sentinelDirACL)
	if err != nil {
		return err
	}
	fileACL, err := nfs4acl.ParseACLSpec(sentinelFileACL)
	if err != nil {
		return err
	}
	// Deepest first, so a restrictive sentinel on a parent cannot lock the walk
	// out of its own children mid-stamp.
	dirs := append([]string{"."}, differentialTree...)
	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i], "/") > strings.Count(dirs[j], "/")
	})
	for _, file := range differentialFiles {
		if err := nfs4acl.SetACL(filepath.Join(root, file), fileACL); err != nil {
			return fmt.Errorf("sentinel on %s: %w", file, err)
		}
	}
	for _, dir := range dirs {
		if err := nfs4acl.SetACL(filepath.Join(root, dir), dirACL); err != nil {
			return fmt.Errorf("sentinel on %s: %w", dir, err)
		}
	}
	return nil
}

// repairTree runs the production walk-and-apply pipeline over one transport.
//
// It goes through walk.Prepass rather than calling ProcessPath on a hand-built
// path list because the userspace transport's whole point is that READDIR
// supplies each object's filehandle; a hand-built list would resolve every path
// by LOOKUP and exercise a code path production never takes.
func repairTree(t transport.Transport, root transport.Ref, sp *spec.Spec) error {
	entries := make(chan walk.Entry, 256)
	var errs walk.WalkErrors

	var applyErr error
	var applyMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range entries {
				res := apply.ProcessPath(t, transport.Ref{Path: e.Path, FH: e.FH}, e.IsDir, sp,
					apply.Options{}, e.Mode)
				if res.Error != nil {
					applyMu.Lock()
					if applyErr == nil {
						applyErr = res.Error
					}
					applyMu.Unlock()
				}
			}
		}()
	}

	result := walk.Prepass(root.Path, entries, &errs, walk.PrepassOptions{
		Transport: t,
		Fix: func(ref transport.Ref) (bool, string, walk.FixResult) {
			// The tree is built traversable, so a fix here means the sentinel or a
			// repair made a directory unreadable. Report it rather than papering
			// over it: silently chmodding would hide exactly the bug this test is
			// for.
			return false, "unexpected unreadable directory " + ref.Path, walk.FixResult{}
		},
		Workers: 8,
	})
	close(entries)
	wg.Wait()

	if applyErr != nil {
		return applyErr
	}
	if result.Errors != 0 || errs.Count() != 0 {
		return fmt.Errorf("walk reported %d fix errors and %d walk errors", result.Errors, errs.Count())
	}
	return nil
}
