package nfs41

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestLiveOpenCreateProbe answers, against real hardware, the questions that
// decide whether generate-tree can create files through the userspace
// transport instead of the kernel mount:
//
//	A. Does CREATE(NF4DIR) accept FATTR4_ACL in createattrs?   (dir + ACL, 1 RPC, stateless)
//	B. Does OPEN(CREATE) work at all from this client?          (baseline, mode only)
//	C. Does OPEN(CREATE) honor FATTR4_ACL in createattrs?       (file + ACL, no separate SETATTR)
//	D. Does the server allow OPEN+GETFH+CLOSE in one COMPOUND?  (1 RPC per file total)
//	E. Does REMOVE work?                                        (userspace cleanup between runs)
//
// Each probe reports PASS/FAIL with the server's status; later probes still
// run when earlier ones fail, because a partial answer still shapes the design.
// FlashBlade's one-mutation-per-COMPOUND forwarding rule is exactly what probe
// D tests: CLOSE is state-only, so the question is whether Purity counts it as
// a mutation.
func TestLiveOpenCreateProbe(t *testing.T) {
	server, export := os.Getenv("PERMISSIONRESET_TEST_SERVER"), os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	if server == "" || export == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER and PERMISSIONRESET_TEST_EXPORT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{
		Server:      server,
		Export:      export,
		Connections: 1,
		RPCTimeout:  30 * time.Second,
		Log:         func(s string) { t.Logf("nfs41: %s", s) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cl.Close()
	t.Logf("server identity: %+v", cl.ServerIdentity())

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	// The export root is rarely writable by the probe's identity; point the
	// probes at a writable subdirectory with PERMISSIONRESET_TEST_DIR (a path
	// relative to the export).
	if sub := os.Getenv("PERMISSIONRESET_TEST_DIR"); sub != "" {
		dirPath := path.Join(root.Path, sub)
		fh, err := cl.resolvePath(ctx, dirPath)
		if err != nil {
			t.Fatalf("resolving PERMISSIONRESET_TEST_DIR %q: %v", sub, err)
		}
		root = transport.Ref{Path: dirPath, FH: fh}
	}

	acl, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwatTnNcCy"})
	if err != nil {
		t.Fatal(err)
	}
	mode := make([]byte, 4)
	binary.BigEndian.PutUint32(mode, 0644)
	dirMode := make([]byte, 4)
	binary.BigEndian.PutUint32(dirMode, 0755)

	session := cl.pool[0].session
	clientid := xdr.Clientid4(session.reg.id)
	owner := []byte(fmt.Sprintf("openprobe-%d", os.Getpid()))
	unique := fmt.Sprintf("openprobe-%d", os.Getpid())

	do := func(label string, ops []xdr.Nfs_argop4) (uint32, []xdr.Nfs_resop4) {
		status, results, err := session.Do(ctx, ops)
		if err != nil {
			t.Fatalf("%s: transport error: %v", label, err)
		}
		return status, results
	}

	readBackACL := func(label string, fh []byte, want []byte) {
		got, err := cl.GetACL(transport.Ref{Path: path.Join(root.Path, label), FH: fh})
		if err != nil {
			t.Logf("  readback GetACL failed: %v", err)
			return
		}
		if bytes.Equal(got, want) {
			t.Logf("  readback: ACL matches byte-for-byte")
		} else {
			t.Logf("  readback: ACL DIFFERS (server rewrote it) — got %d bytes, want %d", len(got), len(want))
		}
	}

	// ---- Probe A: CREATE(NF4DIR) with mode+ACL createattrs, plus GETFH ----
	dirName := unique + "-dir"
	{
		bitmap, attrs := EncodeAttrList([]uint32{fattr4ACL, fattr4Mode}, [][]byte{acl, dirMode})
		op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE}
		ca := op.Opcreate()
		ca.Objtype.Type = xdr.NF4DIR
		ca.Objname = xdr.Component4(dirName)
		ca.Createattrs = xdr.Fattr4{Attrmask: bitmap, Attr_vals: attrs}

		status, results := do("probe A", []xdr.Nfs_argop4{OpPutFH(root.FH), op, OpGetFH()})
		if status != NFS4_OK {
			t.Logf("PROBE A FAIL: CREATE dir+ACL status %s (%d)", xdr.Nfsstat4(status), status)
		} else {
			res := results[2].Opcreate().Resok4()
			t.Logf("PROBE A PASS: CREATE dir+ACL in one COMPOUND; attrset %v", res.Attrset)
			fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
			readBackACL(dirName, fh, acl)
		}
	}

	// ---- Probe B: OPEN(CREATE, GUARDED) mode only, + GETFH; CLOSE separately ----
	openCreate := func(name string, bits []uint32, values [][]byte) xdr.Nfs_argop4 {
		bitmap, attrs := EncodeAttrList(bits, values)
		op := xdr.Nfs_argop4{Argop: xdr.OP_OPEN}
		oa := op.Opopen()
		oa.Seqid = 0 // ignored in v4.1 (RFC 5661 §8.13)
		oa.Share_access = xdr.OPEN4_SHARE_ACCESS_WRITE
		oa.Share_deny = xdr.OPEN4_SHARE_DENY_NONE
		oa.Owner = xdr.Open_owner4{Clientid: clientid, Owner: owner}
		oa.Openhow.Opentype = xdr.OPEN4_CREATE
		how := oa.Openhow.How()
		how.Mode = xdr.GUARDED4
		*how.Createattrs() = xdr.Fattr4{Attrmask: bitmap, Attr_vals: attrs}
		oa.Claim.Claim = xdr.CLAIM_NULL
		*oa.Claim.File() = xdr.Component4(name)
		return op
	}
	closeOp := func(stateid xdr.Stateid4) xdr.Nfs_argop4 {
		op := xdr.Nfs_argop4{Argop: xdr.OP_CLOSE}
		ca := op.Opclose()
		ca.Seqid = 0
		ca.Open_stateid = stateid
		return op
	}

	fileB := unique + "-file-mode"
	{
		status, results := do("probe B open",
			[]xdr.Nfs_argop4{OpPutFH(root.FH), openCreate(fileB, []uint32{fattr4Mode}, [][]byte{mode}), OpGetFH()})
		if status != NFS4_OK {
			t.Logf("PROBE B FAIL: OPEN(CREATE) status %s (%d)", xdr.Nfsstat4(status), status)
		} else {
			ok := results[2].Opopen().Resok4()
			fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
			t.Logf("PROBE B PASS: OPEN(CREATE) works; rflags %#x delegation %d", ok.Rflags, ok.Delegation.Delegation_type)
			cstatus, _ := do("probe B close", []xdr.Nfs_argop4{OpPutFH(fh), closeOp(ok.Stateid)})
			if cstatus != NFS4_OK {
				t.Logf("  CLOSE (separate COMPOUND) status %s (%d)", xdr.Nfsstat4(cstatus), cstatus)
			} else {
				t.Logf("  CLOSE (separate COMPOUND) OK — 2 RPCs per file floor confirmed")
			}
		}
	}

	// ---- Probe C: OPEN(CREATE) with mode+ACL createattrs ----
	fileC := unique + "-file-acl"
	{
		status, results := do("probe C",
			[]xdr.Nfs_argop4{OpPutFH(root.FH), openCreate(fileC, []uint32{fattr4ACL, fattr4Mode}, [][]byte{acl, mode}), OpGetFH()})
		if status != NFS4_OK {
			t.Logf("PROBE C FAIL: OPEN(CREATE)+ACL status %s (%d)", xdr.Nfsstat4(status), status)
		} else {
			ok := results[2].Opopen().Resok4()
			fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
			t.Logf("PROBE C PASS: OPEN(CREATE) accepted FATTR4_ACL; attrset %v", ok.Attrset)
			readBackACL(fileC, fh, acl)
			do("probe C close", []xdr.Nfs_argop4{OpPutFH(fh), closeOp(ok.Stateid)})
		}
	}

	// ---- Probe D: OPEN+GETFH+CLOSE in ONE COMPOUND ----
	fileD := unique + "-file-onerpc"
	{
		// CLOSE needs the stateid OPEN returns, which is unknowable when building
		// the COMPOUND. RFC 5661 §8.2.3 defines the "current stateid" for exactly
		// this: a special stateid of seqid=1, other=all-zero refers to the
		// COMPOUND's current stateid, set by the preceding OPEN.
		current := xdr.Stateid4{Seqid: 1}
		status, results := do("probe D",
			[]xdr.Nfs_argop4{OpPutFH(root.FH), openCreate(fileD, []uint32{fattr4ACL, fattr4Mode}, [][]byte{acl, mode}), OpGetFH(), closeOp(current)})
		if status != NFS4_OK {
			n := len(results)
			t.Logf("PROBE D FAIL: OPEN+GETFH+CLOSE one COMPOUND status %s (%d) after %d results", xdr.Nfsstat4(status), status, n)
			// If OPEN succeeded but CLOSE was refused, the file exists with an
			// open hanging; close it separately so cleanup can proceed.
			if n >= 4 && results[2].Resop == xdr.OP_OPEN {
				if or := results[2].Opopen(); uint32(or.Status) == NFS4_OK {
					fh := append([]byte(nil), results[3].Opgetfh().Resok4().Object...)
					do("probe D recovery close", []xdr.Nfs_argop4{OpPutFH(fh), closeOp(or.Resok4().Stateid)})
				}
			}
		} else {
			t.Logf("PROBE D PASS: one RPC per file — OPEN+GETFH+CLOSE accepted in a single COMPOUND")
		}
	}

	// ---- Probe E: REMOVE (cleanup, and answers whether userspace can clean up) ----
	for _, name := range []string{fileB, fileC, fileD, dirName} {
		op := xdr.Nfs_argop4{Argop: xdr.OP_REMOVE}
		op.Opremove().Target = xdr.Component4(name)
		status, _ := do("probe E remove "+name, []xdr.Nfs_argop4{OpPutFH(root.FH), op})
		if status != NFS4_OK {
			t.Logf("PROBE E: REMOVE %s status %s (%d)", name, xdr.Nfsstat4(status), status)
		} else {
			t.Logf("PROBE E: REMOVE %s OK", name)
		}
	}
}
