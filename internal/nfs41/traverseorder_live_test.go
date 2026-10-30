package nfs41

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestDirectoryFixDoesNotGateItsChildrenInTheSameCompound answers the one
// question COMPOUND batching raised that a fake server cannot answer.
//
// A bundle may carry a directory's own SETATTR alongside SETATTRs for objects
// beneath it. If the directory's new ACL removes traverse for the running
// principal, and the array authorizes a SETATTR by walking the object's
// ancestors rather than by consulting the object itself, then the children in
// that COMPOUND fail with NFS4ERR_ACCESS -- and, by RFC 8881 section 15.2, every
// operation after the first failure is never executed.
//
// This cannot be settled against the fake server. The fake authorizes per object
// because that is how it is written, so a passing test there would assert the
// fake's own construction. It also cannot be settled by any measurement taken so
// far: the lab client runs as root under no_root_squash, so every benchmark runs
// as uid 0 and a principal-specific refusal is invisible in all of them.
//
// The protocol argues that this is safe. PUTFH takes an already-resolved
// filehandle, so there is no pathname to walk and nothing for the server to
// check ancestors of -- filehandle-addressed access bypassing path traversal is
// long-standing NFS behavior. But "argues" is why this test exists.
//
// Note what is NOT specific to batching: walk.go emits a directory's own entry
// after its children are enumerated, so a child's SETATTR can already land after
// its parent's restrictive ACL today, in a separate RPC. If this test finds the
// array does enforce ancestor checks, that is a pre-existing bug and not a
// regression introduced by bundling.
//
// The test needs a NON-ROOT principal, and a directory it may modify. It creates
// nothing: point it at a throwaway directory containing at least one regular
// file. It restores the directory's original ACL before returning, including on
// failure. If the restore itself fails the directory is left without traverse
// for the running principal, which is recoverable as root over the mount --
// no_root_squash is what makes that recovery possible.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.54:2049 \
//	PERMISSIONRESET_TEST_EXPORT=/bench-perms \
//	PERMISSIONRESET_TRAVERSE_DIR=/bench-perms/probe-traverse \
//	  go test ./internal/nfs41/ -run TestDirectoryFixDoesNotGate -v
func TestDirectoryFixDoesNotGateItsChildrenInTheSameCompound(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}
	if os.Geteuid() == 0 {
		t.Fatal("this probe is meaningless as root: no_root_squash means uid 0 is " +
			"authorized whatever the ACL says. Run it as an ordinary user.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{
		Server:      server,
		Export:      export,
		Target:      dir,
		Connections: 1,
		RPCTimeout:  30 * time.Second,

		AllowNonPureServer: allowNonPureServer(),
	})
	if err != nil {
		t.Fatalf("client for %s: %v", dir, err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}

	// Pick a regular file below the directory. Its filehandle comes from READDIR,
	// which is exactly where the batching code gets the filehandles it bundles.
	entries, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var childName string
	var childFH []byte
	for _, entry := range entries {
		if entry.IsDir || entry.IsSymlink || len(entry.Ref.FH) == 0 {
			continue
		}
		childName = entry.Name
		childFH = entry.Ref.FH
		break
	}
	if len(childFH) == 0 {
		t.Fatalf("%s has no regular file to use as the bundled child", dir)
	}
	t.Logf("directory %s, bundled child %q", dir, childName)

	// The child's SETATTR re-stamps the ACL it already has, so the probe changes
	// nothing about the child. Only its authorization is under test.
	childRef := transport.Ref{Path: dir + "/" + childName, FH: childFH}
	childACL, err := cl.GetACL(childRef)
	if err != nil {
		t.Fatalf("read the child's ACL: %v", err)
	}
	originalDirACL, err := cl.GetACL(root)
	if err != nil {
		t.Fatalf("read the directory's ACL: %v", err)
	}

	// Deny traverse, keep write-ACL. Denying 'x' is what removes traverse for a
	// principal; keeping 'C' is what lets this test put the directory back. Both
	// OWNER@ and EVERYONE@ are denied because which of the two the array maps
	// this principal to is not something the test should assume.
	restrictive, err := nfs4acl.ParseACLSpec([]string{
		"D::OWNER@:x",
		"D::EVERYONE@:x",
		"A::OWNER@:rwatTcCy",
	})
	if err != nil {
		t.Fatalf("build the restrictive ACL: %v", err)
	}

	restored := false
	defer func() {
		if restored {
			return
		}
		if err := cl.SetACL(root, originalDirACL); err != nil {
			t.Errorf("RESTORE FAILED on %s: %v -- the directory has no traverse for "+
				"this principal. Fix it as root over the mount.", dir, err)
		}
	}()

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}

	// Arm 1, the question: one COMPOUND that fixes the directory and then a child
	// beneath it, in that order, exactly as a bundle would.
	status, results, err := cl.sessionDo(ctx, entry, []xdr.Nfs_argop4{
		OpPutFH(root.FH),
		OpSetACL(restrictive),
		OpPutFH(childFH),
		OpSetACL(childACL),
	})
	if err != nil {
		t.Fatalf("bundled COMPOUND: %v", err)
	}
	// RFC 8881 section 15.2: a COMPOUND stops at the first failure and the
	// operations after it are never executed, so the count of results is what says
	// how far the bundle got. Four operations plus the session's SEQUENCE is a
	// complete bundle; fewer means the child's SETATTR was refused or skipped.
	t.Logf("  arm 1: COMPOUND status %d, %d results executed", status, len(results))
	for i, result := range results {
		t.Logf("    op %d: %v", i, result.Resop)
	}

	// Arm 2, the control: prove the restrictive ACL actually took effect, by
	// resolving the same child BY NAME through the directory. This is a
	// protocol-level check on the same session and the same principal, so it does
	// not depend on the kernel mount or on any client cache. If this SUCCEEDS the
	// deny did not take and arm 1 proves nothing.
	lookupStatus, lookupResults, err := cl.sessionDo(ctx, entry, []xdr.Nfs_argop4{
		OpPutFH(root.FH),
		OpLookup(childName),
		OpGetFH(),
	})
	if err != nil {
		t.Fatalf("control LOOKUP: %v", err)
	}
	t.Logf("  arm 2 (LOOKUP by name through the restricted directory): status %d, %d results",
		lookupStatus, len(lookupResults))

	if err := cl.SetACL(root, originalDirACL); err != nil {
		t.Fatalf("restore %s: %v -- the directory has no traverse for this principal; "+
			"fix it as root over the mount", dir, err)
	}
	restored = true

	switch {
	case lookupStatus == NFS4_OK:
		t.Fatalf("INCONCLUSIVE: the directory still resolves %q by name after the "+
			"deny-traverse ACL was set, so the condition under test was never "+
			"created. The array did not honour D::OWNER@:x / D::EVERYONE@:x on a "+
			"directory. Arm 1's status %d says nothing.", childName, status)
	case status == NFS4_OK:
		t.Logf("ANSWER: the array authorizes a PUTFH-addressed SETATTR against the "+
			"object itself. The directory's own restrictive fix does NOT gate "+
			"children bundled behind it in the same COMPOUND (control: LOOKUP by "+
			"name was refused with status %d, so traverse really was removed). "+
			"Bundling a directory with its descendants is safe.", lookupStatus)
	default:
		t.Errorf("ANSWER, and it is the bad one: the bundled COMPOUND returned status "+
			"%d once the directory lost traverse, so the array authorizes SETATTR by "+
			"walking ancestors. A bundle must not carry a directory together with "+
			"objects beneath it -- and note this also makes the existing unbatched "+
			"ordering a pre-existing bug, since walk.go already emits a directory "+
			"after its children.", status)
	}
}

// TestTraverseProbeDiagnostic isolates which part of the bundled COMPOUND the
// array rejects, for when the probe above fails before it can answer anything.
// Each arm is sent on its own so a rejection names one operation rather than a
// shape. It restores the directory's ACL before returning.
func TestTraverseProbeDiagnostic(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{Server: server, Export: export, Target: dir,
		Connections: 1, RPCTimeout: 30 * time.Second,
		AllowNonPureServer: allowNonPureServer()})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	original, err := cl.GetACL(root)
	if err != nil {
		t.Fatalf("read the directory's ACL: %v", err)
	}
	t.Logf("current directory ACL: %d bytes", len(original))

	restrictive, err := nfs4acl.ParseACLSpec([]string{
		"D::OWNER@:x",
		"D::EVERYONE@:x",
		"A::OWNER@:rwatTcCy",
	})
	if err != nil {
		t.Fatalf("build the restrictive ACL: %v", err)
	}
	t.Logf("restrictive ACL: %d bytes, % x", len(restrictive), restrictive)

	// Arm A: the restrictive ACL on its own, through the ordinary client path.
	// If this fails, the ACL bytes are the problem and the bundle shape is
	// exonerated.
	if err := cl.SetACL(root, restrictive); err != nil {
		t.Errorf("arm A, restrictive ACL alone: %v", err)
	} else {
		t.Log("arm A: the array accepted the deny-traverse ACL")
		if err := cl.SetACL(root, original); err != nil {
			t.Errorf("arm A restore: %v", err)
		}
	}

	// Arm B: re-stamp the directory's EXISTING ACL as a two-op bundle. A failure
	// here is about the shape, not the ACL, because these are the bytes the array
	// just handed us.
	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	status, results, err := cl.sessionDo(ctx, entry, []xdr.Nfs_argop4{
		OpPutFH(root.FH),
		OpSetACL(original),
	})
	if err != nil {
		t.Errorf("arm B, PUTFH+SETACL with the array's own bytes: %v", err)
	} else {
		t.Logf("arm B: status %d, %d results", status, len(results))
	}

	// Arm C: two PUTFH+SETACL pairs in one COMPOUND, both on the directory, both
	// with its existing ACL. This is the bundle shape with nothing restrictive in
	// it, which separates "four operations" from "a directory losing traverse".
	status, results, err = cl.sessionDo(ctx, entry, []xdr.Nfs_argop4{
		OpPutFH(root.FH),
		OpSetACL(original),
		OpPutFH(root.FH),
		OpSetACL(original),
	})
	if err != nil {
		t.Errorf("arm C, two pairs in one COMPOUND: %v", err)
	} else {
		t.Logf("arm C: status %d, %d results", status, len(results))
	}
}

// TestBundleShapeDiagnostic finds which COMPOUND shapes the array accepts.
//
// It sends each shape WITHOUT a SEQUENCE, straight down the connection, for one
// reason: Session.Do rejects a reply whose first result is not SEQUENCE, which
// hides the array's actual status behind a generic error. The raw path gives the
// status code. TestCaptureReadDirReply establishes that this array answers a
// sessionless COMPOUND, so the shape under test is the only variable.
//
// Every SETACL here re-stamps the ACL the array itself just returned, so no arm
// changes anything.
func TestBundleShapeDiagnostic(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{Server: server, Export: export, Target: dir,
		Connections: 1, RPCTimeout: 30 * time.Second,
		AllowNonPureServer: allowNonPureServer()})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	acl, err := cl.GetACL(root)
	if err != nil {
		t.Fatalf("read the directory's ACL: %v", err)
	}
	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}

	fh := root.FH
	shapes := []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		{"PUTFH+GETATTR", []xdr.Nfs_argop4{OpPutFH(fh), OpGetAttr(fattr4Mode)}},
		{"PUTFH+GETATTR+PUTFH+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(fh), OpGetAttr(fattr4Mode), OpPutFH(fh), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL", []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(acl)}},
		{"PUTFH+SETACL+GETATTR", []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(acl), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL+PUTFH", []xdr.Nfs_argop4{OpPutFH(fh), OpSetACL(acl), OpPutFH(fh)}},
		{"PUTFH+SETACL+PUTFH+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(fh), OpSetACL(acl), OpPutFH(fh), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL+PUTFH+SETACL", []xdr.Nfs_argop4{
			OpPutFH(fh), OpSetACL(acl), OpPutFH(fh), OpSetACL(acl)}},
		{"PUTFH+SETACL x3", []xdr.Nfs_argop4{
			OpPutFH(fh), OpSetACL(acl), OpPutFH(fh), OpSetACL(acl), OpPutFH(fh), OpSetACL(acl)}},
	}

	for _, shape := range shapes {
		request, err := BuildCompound("shape", shape.ops)
		if err != nil {
			t.Errorf("%s: build: %v", shape.name, err)
			continue
		}
		reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if err != nil {
			t.Errorf("%-30s CALL FAILED: %v", shape.name, err)
			continue
		}
		status, results, err := ParseCompound(reply)
		if err != nil {
			t.Errorf("%-30s UNPARSEABLE: %v", shape.name, err)
			continue
		}
		t.Logf("%-30s status %-3d results %d/%d", shape.name, status, len(results), len(shape.ops))
	}
}

// TestTwoSetattrsOnDistinctObjects is the decisive arm for COMPOUND batching.
//
// TestBundleShapeDiagnostic found that a second SETATTR in one COMPOUND is
// refused with NFS4ERR_INVAL and zero results, but every pair there addressed
// the SAME filehandle. Batching addresses a different object per pair, which is
// the case that decides whether SEQUENCE + 7x(PUTFH,SETATTR) can be sent at all.
//
// Every SETACL re-stamps the ACL the array just returned for that object, and
// every mode is the object's own mode, so no arm changes anything.
func TestTwoSetattrsOnDistinctObjects(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{Server: server, Export: export, Target: dir,
		Connections: 1, RPCTimeout: 30 * time.Second,
		AllowNonPureServer: allowNonPureServer()})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	entries, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	type object struct {
		name string
		fh   []byte
		acl  []byte
		mode uint32
	}
	var files []object
	for _, e := range entries {
		if e.IsDir || e.IsSymlink || len(e.Ref.FH) == 0 {
			continue
		}
		ref := transport.Ref{Path: dir + "/" + e.Name, FH: e.Ref.FH}
		acl, err := cl.GetACL(ref)
		if err != nil {
			t.Fatalf("read %s ACL: %v", e.Name, err)
		}
		attr, err := cl.Stat(ref)
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name, err)
		}
		files = append(files, object{e.Name, e.Ref.FH, acl, attr.Mode})
	}
	if len(files) < 2 {
		t.Fatalf("need at least two regular files below %s, found %d", dir, len(files))
	}
	t.Logf("using %s and %s", files[0].name, files[1].name)

	dirACL, err := cl.GetACL(root)
	if err != nil {
		t.Fatalf("read the directory's ACL: %v", err)
	}
	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}

	mode := func(m uint32) xdr.Nfs_argop4 {
		var value [4]byte
		value[0] = byte(m >> 24)
		value[1] = byte(m >> 16)
		value[2] = byte(m >> 8)
		value[3] = byte(m)
		return OpSetAttr([]uint32{fattr4Mode}, [][]byte{value[:]})
	}

	shapes := []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		{"2 SETACL, DISTINCT files", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[1].fh), OpSetACL(files[1].acl)}},
		{"2 SETACL, dir then child", []xdr.Nfs_argop4{
			OpPutFH(root.FH), OpSetACL(dirACL),
			OpPutFH(files[0].fh), OpSetACL(files[0].acl)}},
		{"2 SETATTR mode, DISTINCT files", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), mode(files[0].mode),
			OpPutFH(files[1].fh), mode(files[1].mode)}},
		{"SETACL then SETATTR mode, distinct", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[1].fh), mode(files[1].mode)}},
		{"3 SETACL, distinct where possible", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[1].fh), OpSetACL(files[1].acl),
			OpPutFH(root.FH), OpSetACL(dirACL)}},
	}

	for _, shape := range shapes {
		request, err := BuildCompound("distinct", shape.ops)
		if err != nil {
			t.Errorf("%s: build: %v", shape.name, err)
			continue
		}
		reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if err != nil {
			t.Errorf("%-34s CALL FAILED: %v", shape.name, err)
			continue
		}
		status, results, err := ParseCompound(reply)
		if err != nil {
			t.Errorf("%-34s UNPARSEABLE: %v", shape.name, err)
			continue
		}
		t.Logf("%-34s status %-3d results %d/%d", shape.name, status, len(results), len(shape.ops))
	}
}

// TestRefusedCompoundHasNoSideEffects checks the one property that decides
// whether a refused bundle is safe to retry.
//
// A COMPOUND carrying two SETATTRs is refused with NFS4ERR_INVAL and zero
// results. Zero results is strong evidence that nothing ran, but it is not
// proof: a server could execute the first SETATTR, discover it cannot forward
// the second, and reset the response. If that were what happened, a refused
// bundle would be PARTIALLY APPLIED, and any caller that retried it -- or that
// treated the refusal as "nothing happened" -- would be wrong.
//
// So this arm makes the first SETATTR observable: it sets a DIFFERENT ACL on the
// first object, pairs it with a second SETATTR to force the refusal, and reads
// the first object's ACL back. It restores the original either way.
func TestRefusedCompoundHasNoSideEffects(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{Server: server, Export: export, Target: dir,
		Connections: 1, RPCTimeout: 30 * time.Second,
		AllowNonPureServer: allowNonPureServer()})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	entries, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var refs []transport.Ref
	for _, e := range entries {
		if e.IsDir || e.IsSymlink || len(e.Ref.FH) == 0 {
			continue
		}
		refs = append(refs, transport.Ref{Path: dir + "/" + e.Name, FH: e.Ref.FH})
	}
	if len(refs) < 2 {
		t.Fatalf("need two regular files below %s, found %d", dir, len(refs))
	}

	original, err := cl.GetACL(refs[0])
	if err != nil {
		t.Fatalf("read %s ACL: %v", refs[0].Path, err)
	}
	other, err := cl.GetACL(refs[1])
	if err != nil {
		t.Fatalf("read %s ACL: %v", refs[1].Path, err)
	}

	// An ACL that is valid, harmless, and DIFFERENT from what the object has, so
	// that a partial application is visible on read-back.
	marker, err := nfs4acl.ParseACLSpec([]string{
		"A::OWNER@:rwatTcCy",
		"A::GROUP@:rtcy",
		"A::EVERYONE@:tcy",
	})
	if err != nil {
		t.Fatalf("build the marker ACL: %v", err)
	}
	if bytes.Equal(marker, original) {
		t.Skip("the marker ACL matches the object's current ACL, so a partial " +
			"application would be invisible; change the marker")
	}

	defer func() {
		if err := cl.SetACL(refs[0], original); err != nil {
			t.Errorf("restore %s: %v", refs[0].Path, err)
		}
	}()

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	request, err := BuildCompound("side-effects", []xdr.Nfs_argop4{
		OpPutFH(refs[0].FH), OpSetACL(marker),
		OpPutFH(refs[1].FH), OpSetACL(other),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	status, results, err := ParseCompound(reply)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Logf("refused COMPOUND: status %d, %d results", status, len(results))
	if status == NFS4_OK {
		t.Fatalf("the array ACCEPTED two SETATTRs; the premise of this test is gone")
	}

	after, err := cl.GetACL(refs[0])
	if err != nil {
		t.Fatalf("re-read %s ACL: %v", refs[0].Path, err)
	}
	switch {
	case bytes.Equal(after, original):
		t.Logf("ANSWER: no side effects. The refused COMPOUND left %s unchanged, so a "+
			"refusal really does mean nothing ran and a caller may treat it as such.",
			refs[0].Path)
	case bytes.Equal(after, marker):
		t.Errorf("ANSWER, and it is the dangerous one: the refused COMPOUND APPLIED its "+
			"first SETATTR to %s. A refusal is a partial application, so it must never be "+
			"treated as 'nothing happened', and the fake server's refusal (which has no "+
			"side effects) is wrong.", refs[0].Path)
	default:
		t.Errorf("%s ACL is neither the original nor the marker after a refused COMPOUND: "+
			"% x", refs[0].Path, after)
	}
}

// allowNonPureServer lets these probes run against a server whose
// FATTR4_MAXFILESIZE is not yet in pureMaxFileSizes.
//
// The gate in New() exists so that a production run cannot be pointed at a
// server this transport was never validated against. Establishing whether a
// given array accepts a shape is exactly the work that has to happen BEFORE
// that validation exists, so a probe needs a way past it -- and the only other
// way past is to add the array's value to pureMaxFileSizes, which would assert
// the validation these probes are being run to perform.
//
// It is off unless asked for, and it is read from the environment rather than
// hardcoded so that the default arm of every probe is still the gated one.
func allowNonPureServer() bool {
	return os.Getenv("PERMISSIONRESET_TEST_ALLOW_NON_PURE") == "1"
}
