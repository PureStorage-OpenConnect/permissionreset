package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestBundleBounds finds the largest bundle each array accepts, per operation
// class, by sweeping N until it is refused.
//
// It exists because the per-platform bundling design needs three numbers that
// were never measured, and hardcoding a guess as a capability constant is the
// failure mode to avoid:
//
//   - FlashBlade's GETATTR cap. Read from the Purity source as
//     k_max_getattr_ops_allowed = 4 (nfs.cpp:12408) and never measured; only two
//     GETATTRs in one COMPOUND were ever sent.
//   - FlashArray's mutation cap. Measured at 2 and 3 SETATTRs. The design point
//     is 7.
//   - FlashArray's read cap. Entirely unknown.
//
// A sweep rather than fixed shapes, because the question is where the boundary
// is, not whether one chosen shape sits on the safe side of it. Each arm reports
// every N with its status, so a cap of 4 and a cap of 6 are distinguishable
// instead of both reading as "the shape I picked worked".
//
// Every arm is non-destructive. The mutation arms re-stamp the ACL the array
// itself just returned for that object, and the read arms only read.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.200:2049 \
//	PERMISSIONRESET_TEST_EXPORT=/probe \
//	PERMISSIONRESET_TRAVERSE_DIR=/probe/bounds \
//	PERMISSIONRESET_TEST_ALLOW_NON_PURE=1 \
//	  ./nfs41.test -test.run TestBundleBounds -test.v
func TestBundleBounds(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
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
	}
	var files []object
	var dirs []object
	for _, e := range entries {
		if e.IsSymlink || len(e.Ref.FH) == 0 {
			continue
		}
		ref := transport.Ref{Path: dir + "/" + e.Name, FH: e.Ref.FH}
		acl, err := cl.GetACL(ref)
		if err != nil {
			t.Fatalf("read %s ACL: %v", e.Name, err)
		}
		if e.IsDir {
			dirs = append(dirs, object{e.Name, e.Ref.FH, acl})
			continue
		}
		files = append(files, object{e.Name, e.Ref.FH, acl})
	}
	t.Logf("found %d regular files and %d directories below %s", len(files), len(dirs), dir)
	if len(files) < 2 {
		t.Fatalf("need at least two regular files below %s", dir)
	}

	// pick cycles through the available objects so an arm asking for more members
	// than the directory holds still addresses a spread of filehandles rather
	// than failing to run. Reusing a filehandle is known to behave identically to
	// distinct ones for the mutation limit, so cycling does not change what the
	// sweep measures -- but it is logged, so a short directory cannot silently
	// look like a clean result.
	pick := func(list []object, i int) object { return list[i%len(list)] }

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	session := entry.session
	attrs := session.ChannelAttrs()
	t.Logf("negotiated channel: maxoperations=%d maxrequestsize=%d maxresponsesize=%d",
		attrs.MaxOperations, attrs.MaxRequestSize, attrs.MaxResponseSize)

	// send returns (status, resultCount, detail, ok). ok is false when the call
	// itself failed, which must NOT read as an accepted shape -- an earlier
	// version returned status 0 for a transport error and the sweep reported the
	// largest refused bundle as its largest accepted one.
	//
	// SLOT ACCOUNTING IS THE SUBTLE PART, and getting it wrong invalidates every
	// arm after the first refusal. RFC 8881 section 2.203.0.113.2: an error from
	// SEQUENCE does not consume the slot's sequence ID. So a COMPOUND refused AT
	// SEQUENCE -- which is how both arrays answer an over-budget op count -- must
	// have its slot RECLAIMED, not released. Releasing advances a seqid the server
	// never saw, and every subsequent call on that slot earns
	// NFS4ERR_SEQ_MISORDERED (10063). That is exactly what the first run of this
	// probe did: FlashArray's read arms all reported 10063 at every N, including
	// shapes already known to work, because the 17-operation arm ahead of them had
	// desynced the slot.
	send := func(ops []xdr.Nfs_argop4) (status uint32, results int, detail string, ok bool) {
		session.stateMu.RLock()
		id := session.id
		table := session.slots
		session.stateMu.RUnlock()

		sl, err := table.acquire(ctx)
		if err != nil {
			return 0, 0, "acquire: " + err.Error(), false
		}
		compound := make([]xdr.Nfs_argop4, 1, len(ops)+1)
		compound[0] = OpSequence(id, sl.seqID, sl.id, uint32(table.size()-1))
		compound = append(compound, ops...)
		request, err := BuildCompound("bounds", compound)
		if err != nil {
			table.reclaim(sl)
			return 0, 0, "build: " + err.Error(), false
		}
		reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if err != nil {
			// The server rejected the record without decoding it, so SEQUENCE did
			// not run and the seqid is unspent.
			table.reclaim(sl)
			return 0, 0, "call: " + err.Error(), false
		}
		st, res, err := ParseCompound(reply)
		if err != nil {
			table.release(sl)
			return 0, 0, "parse: " + err.Error(), false
		}
		// Reclaim when SEQUENCE itself failed; release otherwise.
		seqFailed := len(res) > 0 && res[0].Resop == xdr.OP_SEQUENCE &&
			uint32(res[0].Opsequence().Sr_status) != 0
		if seqFailed || len(res) == 0 {
			table.reclaim(sl)
		} else {
			table.release(sl)
		}
		status, results = uint32(st), len(res)
		// The COMPOUND status is only the last result's, so the first non-zero
		// result is what actually names the offending operation.
		var first string
		for i, r := range res {
			var opStatus uint32
			switch r.Resop {
			case xdr.OP_SEQUENCE:
				opStatus = uint32(r.Opsequence().Sr_status)
			case xdr.OP_PUTFH:
				opStatus = uint32(r.Opputfh().Status)
			case xdr.OP_SETATTR:
				opStatus = uint32(r.Opsetattr().Status)
			case xdr.OP_GETATTR:
				opStatus = uint32(r.Opgetattr().Status)
			case xdr.OP_READDIR:
				opStatus = uint32(r.Opreaddir().Status)
			}
			if opStatus != 0 && first == "" {
				first = fmt.Sprintf("  first failure: op %d (%v) %v", i, r.Resop, xdr.Nfsstat4(opStatus))
			}
		}
		return status, results, first, true
	}

	// Each arm builds N members. The op count is reported alongside so a refusal
	// driven by the 16-operation ceiling is not mistaken for a class-specific cap.
	arms := []struct {
		name  string
		limit int
		build func(n int) []xdr.Nfs_argop4
	}{
		{"SETACL on distinct files", 9, func(n int) []xdr.Nfs_argop4 {
			var ops []xdr.Nfs_argop4
			for i := range n {
				o := pick(files, i)
				ops = append(ops, OpPutFH(o.fh), OpSetACL(o.acl))
			}
			return ops
		}},
		{"GETATTR(mode) on distinct files", 9, func(n int) []xdr.Nfs_argop4 {
			var ops []xdr.Nfs_argop4
			for i := range n {
				ops = append(ops, OpPutFH(pick(files, i).fh), OpGetAttr(fattr4Mode))
			}
			return ops
		}},
		// GETATTR(ACL) is the operation --compare actually issues, and it returns
		// a far larger reply than the mode. If a cap is on reply size rather than
		// on op count, these two arms diverge.
		{"GETATTR(ACL) on distinct files", 9, func(n int) []xdr.Nfs_argop4 {
			var ops []xdr.Nfs_argop4
			for i := range n {
				ops = append(ops, OpPutFH(pick(files, i).fh), OpGetAttr(fattr4ACL))
			}
			return ops
		}},
		// Repeated GETATTR on ONE filehandle with no intervening PUTFH isolates
		// the per-COMPOUND GETATTR count from the PUTFH count.
		{"GETATTR(mode) repeated, one PUTFH", 12, func(n int) []xdr.Nfs_argop4 {
			ops := []xdr.Nfs_argop4{OpPutFH(files[0].fh)}
			for range n {
				ops = append(ops, OpGetAttr(fattr4Mode))
			}
			return ops
		}},
	}

	if len(dirs) > 0 {
		arms = append(arms, struct {
			name  string
			limit int
			build func(n int) []xdr.Nfs_argop4
		}{"READDIR on distinct directories", 7, func(n int) []xdr.Nfs_argop4 {
			// maxcount is divided by n so the bundle's replies together stay
			// inside ca_maxresponsesize. That is the constraint that actually
			// binds a READDIR bundle, and not dividing it would measure the
			// response ceiling while appearing to measure an op cap.
			each := attrs.MaxResponseSize / uint32(n+1)
			if each > 64<<10 {
				each = 64 << 10
			}
			var ops []xdr.Nfs_argop4
			for i := range n {
				ops = append(ops, OpPutFH(pick(dirs, i).fh),
					OpReadDir(0, [8]byte{}, each, each, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID))
			}
			return ops
		}})
	}

	for _, arm := range arms {
		t.Logf("--- %s", arm.name)
		accepted := 0
		for n := 1; n <= arm.limit; n++ {
			ops := arm.build(n)
			status, results, detail, ok := send(ops)
			verdict := "ACCEPTED"
			switch {
			case !ok:
				verdict = "ERROR"
			case status != 0:
				verdict = "refused"
			default:
				accepted = n
			}
			t.Logf("    n=%-3d ops=%-3d %-8s %-24v results %d%s",
				n, len(ops)+1, verdict, xdr.Nfsstat4(status), results, detail)
		}
		t.Logf("    => largest accepted %s: %d", arm.name, accepted)
	}
}
