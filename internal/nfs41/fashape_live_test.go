package nfs41

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestSessionCompoundShapes asks the same question TestBundleShapeDiagnostic
// asks -- does this array accept more than one mutating operation in a single
// COMPOUND -- but it asks it inside a session.
//
// It exists because the sessionless approach that worked on FlashBlade does not
// work everywhere. FlashBlade answers a COMPOUND with no leading SEQUENCE, so
// that probe could bypass Session.Do (which rejects any reply whose first result
// is not SEQUENCE, hiding the array's real status behind a generic error) and
// read the status directly. FlashArray refuses every such COMPOUND with
// NFS4ERR_OP_NOT_IN_SESSION (10071) -- uniformly, including a bare
// PUTFH+GETATTR -- so on FlashArray the sessionless probe measures only that
// sessionless COMPOUNDs are refused, which says nothing about batching. Reading
// the earlier FlashArray run as "batching is refused" would have been wrong for
// exactly this reason.
//
// So this test supplies the SEQUENCE itself, using the session's own slot
// table, and then parses the reply raw. That is the one thing Session.Do cannot
// give: a status code for a reply with zero results.
//
// Slot accounting follows Session.do's rule for a reply it cannot decode: the
// record reached the server, so the slot's sequence ID is spent and the slot is
// released rather than reclaimed. Reclaiming would reuse a spent seqid and earn
// NFS4ERR_SEQ_MISORDERED on the next call.
//
// Every SETACL re-stamps the ACL the array itself just returned, and every mode
// is the object's own mode, so no arm changes anything.
func TestSessionCompoundShapes(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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
	dirACL, err := cl.GetACL(root)
	if err != nil {
		t.Fatalf("read the directory's ACL: %v", err)
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

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	session := entry.session

	mode := func(m uint32) xdr.Nfs_argop4 {
		var value [4]byte
		value[0] = byte(m >> 24)
		value[1] = byte(m >> 16)
		value[2] = byte(m >> 8)
		value[3] = byte(m)
		return OpSetAttr([]uint32{fattr4Mode}, [][]byte{value[:]})
	}

	// sendRaw is Session.do's body up to the point where it stops trusting the
	// reply, and no further: it supplies SEQUENCE from the live slot table and
	// returns whatever came back, parsed but unvalidated.
	// perOpStatus names the status of each result. The COMPOUND status is only
	// the LAST result's status, so a shape that reports a failure gives no clue
	// as to which operation failed -- and on FlashArray one shape does.
	perOpStatus := func(results []xdr.Nfs_resop4) string {
		out := ""
		for _, r := range results {
			var st uint32
			switch r.Resop {
			case xdr.OP_SEQUENCE:
				st = uint32(r.Opsequence().Sr_status)
			case xdr.OP_PUTFH:
				st = uint32(r.Opputfh().Status)
			case xdr.OP_SETATTR:
				st = uint32(r.Opsetattr().Status)
			case xdr.OP_GETATTR:
				st = uint32(r.Opgetattr().Status)
			default:
				out += fmt.Sprintf(" op%d=?", r.Resop)
				continue
			}
			out += fmt.Sprintf(" %v=%d", r.Resop, st)
		}
		return out
	}

	sendRaw := func(ops []xdr.Nfs_argop4) (uint32, int, string, error) {
		session.stateMu.RLock()
		id := session.id
		table := session.slots
		session.stateMu.RUnlock()

		sl, err := table.acquire(ctx)
		if err != nil {
			return 0, 0, "", err
		}
		compound := make([]xdr.Nfs_argop4, 1, len(ops)+1)
		compound[0] = OpSequence(id, sl.seqID, sl.id, uint32(table.size()-1))
		compound = append(compound, ops...)

		request, err := BuildCompound("fashape", compound)
		if err != nil {
			table.reclaim(sl)
			return 0, 0, "", err
		}
		reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if err != nil {
			table.release(sl)
			return 0, 0, "", err
		}
		// Released, not reclaimed: see the slot-accounting note above.
		defer table.release(sl)
		status, results, err := ParseCompound(reply)
		if err != nil {
			return 0, 0, "", err
		}
		return uint32(status), len(results), perOpStatus(results), nil
	}

	shapes := []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		// The single-mutation arms are the control: if these are refused too,
		// the refusal is not about batching.
		{"PUTFH+GETATTR", []xdr.Nfs_argop4{OpPutFH(root.FH), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL (1 mutation)", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl)}},
		{"PUTFH+SETACL+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl), OpGetAttr(fattr4Mode)}},

		// FlashArray answers the GETATTR in PUTFH+SETACL+GETATTR with
		// NFS4ERR_STALE (70) while the SETATTR itself succeeds, and FlashBlade
		// answers the same shape with NFS4_OK. These arms narrow that down: it is
		// exactly the shape a verify-after-write would send, so which part of it
		// FlashArray objects to decides whether that fold-in is available there.
		{"PUTFH+SETATTR mode+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), mode(files[0].mode), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL+PUTFH+GETATTR", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[0].fh), OpGetAttr(fattr4Mode)}},
		{"PUTFH+SETACL+GETATTR type", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl), OpGetAttr(fattr4Type)}},
		{"PUTFH+GETATTR+SETACL", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpGetAttr(fattr4Mode), OpSetACL(files[0].acl)}},

		// The decisive arms: two or more mutations in one COMPOUND.
		{"2 SETACL, same file", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[0].fh), OpSetACL(files[0].acl)}},
		{"2 SETACL, DISTINCT files", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[1].fh), OpSetACL(files[1].acl)}},
		{"2 SETATTR mode, DISTINCT files", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), mode(files[0].mode),
			OpPutFH(files[1].fh), mode(files[1].mode)}},
		{"2 SETACL, dir then child", []xdr.Nfs_argop4{
			OpPutFH(root.FH), OpSetACL(dirACL),
			OpPutFH(files[0].fh), OpSetACL(files[0].acl)}},
		{"3 SETACL, distinct", []xdr.Nfs_argop4{
			OpPutFH(files[0].fh), OpSetACL(files[0].acl),
			OpPutFH(files[1].fh), OpSetACL(files[1].acl),
			OpPutFH(root.FH), OpSetACL(dirACL)}},
	}

	for _, shape := range shapes {
		status, results, detail, err := sendRaw(shape.ops)
		if err != nil {
			t.Errorf("%-32s FAILED: %v", shape.name, err)
			continue
		}
		t.Logf("%-32s status %-6d results %d/%d  [%s]",
			shape.name, status, results, len(shape.ops)+1, strings.TrimSpace(detail))
	}
}

// TestMultiGetATTRShapes probes how many GETATTR (including GETACL) operations
// the array accepts in a single COMPOUND. The Purity source sets
// k_max_getattr_ops_allowed = 4 on FlashBlade; this test measures the actual
// ceiling rather than trusting the source read.
//
// Run with:
//
//	PERMISSIONRESET_TEST_SERVER=192.0.2.50 \
//	PERMISSIONRESET_TEST_EXPORT=/fb-perms \
//	PERMISSIONRESET_TRAVERSE_DIR=/fb-perms/testdata \
//	go test ./internal/nfs41/ -run TestMultiGetATTRShapes -v -count=1
func TestMultiGetATTRShapes(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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

	// Collect 8 regular-file handles by walking into subdirs if the top
	// level has none (treegen trees keep files several levels deep).
	var fileHandles [][]byte
	queue := []transport.Ref{root}
	for len(fileHandles) < 8 && len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		entries, err := cl.ReadDir(cur)
		if err != nil {
			t.Logf("readdir %x: %v (skipping)", cur.FH[:8], err)
			continue
		}
		for _, e := range entries {
			if e.IsSymlink || len(e.Ref.FH) == 0 {
				continue
			}
			if e.IsDir {
				queue = append(queue, e.Ref)
				continue
			}
			fileHandles = append(fileHandles, e.Ref.FH)
			if len(fileHandles) >= 8 {
				break
			}
		}
	}
	if len(fileHandles) < 8 {
		t.Fatalf("need at least 8 regular files below %s, found %d", dir, len(fileHandles))
	}

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	session := entry.session

	perOpStatus := func(results []xdr.Nfs_resop4) string {
		out := ""
		for _, r := range results {
			var st uint32
			switch r.Resop {
			case xdr.OP_SEQUENCE:
				st = uint32(r.Opsequence().Sr_status)
			case xdr.OP_PUTFH:
				st = uint32(r.Opputfh().Status)
			case xdr.OP_GETATTR:
				st = uint32(r.Opgetattr().Status)
			default:
				out += fmt.Sprintf(" op%d=?", r.Resop)
				continue
			}
			out += fmt.Sprintf(" %v=%d", r.Resop, st)
		}
		return out
	}

	sendRaw := func(ops []xdr.Nfs_argop4) (uint32, int, string, error) {
		session.stateMu.RLock()
		id := session.id
		table := session.slots
		session.stateMu.RUnlock()

		sl, err := table.acquire(ctx)
		if err != nil {
			return 0, 0, "", err
		}
		compound := make([]xdr.Nfs_argop4, 1, len(ops)+1)
		compound[0] = OpSequence(id, sl.seqID, sl.id, uint32(table.size()-1))
		compound = append(compound, ops...)

		request, err := BuildCompound("getattr-probe", compound)
		if err != nil {
			table.reclaim(sl)
			return 0, 0, "", err
		}
		reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if err != nil {
			table.release(sl)
			return 0, 0, "", err
		}
		defer table.release(sl)
		status, results, err := ParseCompound(reply)
		if err != nil {
			return 0, 0, "", err
		}
		return uint32(status), len(results), perOpStatus(results), nil
	}

	// Build N×(PUTFH+GETATTR) with distinct filehandles. Each GETATTR requests
	// the ACL bitmap, which is what --validate and --compare actually read.
	buildGetACLBatch := func(n int) []xdr.Nfs_argop4 {
		ops := make([]xdr.Nfs_argop4, 0, n*2)
		for i := 0; i < n; i++ {
			ops = append(ops, OpPutFH(fileHandles[i]), OpGetAttr(fattr4ACL))
		}
		return ops
	}

	// Same shape but requesting mode instead of ACL, to see if the cap is
	// attribute-specific.
	buildGetModeBatch := func(n int) []xdr.Nfs_argop4 {
		ops := make([]xdr.Nfs_argop4, 0, n*2)
		for i := 0; i < n; i++ {
			ops = append(ops, OpPutFH(fileHandles[i]), OpGetAttr(fattr4Mode))
		}
		return ops
	}

	shapes := []struct {
		name string
		ops  []xdr.Nfs_argop4
	}{
		// Control: single GETATTR with ACL bitmap.
		{"1×GETATTR(ACL)", buildGetACLBatch(1)},

		// The Purity source says k_max_getattr_ops_allowed = 4.
		// Sweep 2 through 7 to find the actual ceiling.
		{"2×GETATTR(ACL)", buildGetACLBatch(2)},
		{"3×GETATTR(ACL)", buildGetACLBatch(3)},
		{"4×GETATTR(ACL)", buildGetACLBatch(4)},
		{"5×GETATTR(ACL)", buildGetACLBatch(5)},
		{"6×GETATTR(ACL)", buildGetACLBatch(6)},
		{"7×GETATTR(ACL)", buildGetACLBatch(7)},

		// Mode instead of ACL, to test whether the cap is attribute-dependent.
		{"4×GETATTR(mode)", buildGetModeBatch(4)},
		{"5×GETATTR(mode)", buildGetModeBatch(5)},

		// Mixed: ACL on some, mode on others.
		{"2×ACL + 2×mode", append(buildGetACLBatch(2), buildGetModeBatch(2)...)},
	}

	t.Log("Each row: name | COMPOUND status | results received/expected | per-op status")
	t.Log("Status 0 = NFS4_OK. Any nonzero status on the last arm is the refusal point.")
	t.Log("")

	for _, shape := range shapes {
		status, results, detail, err := sendRaw(shape.ops)
		if err != nil {
			t.Errorf("%-24s FAILED: %v", shape.name, err)
			continue
		}
		expected := len(shape.ops) + 1 // +1 for SEQUENCE
		verdict := "OK"
		if status != 0 {
			verdict = "REFUSED"
		} else if results != expected {
			verdict = fmt.Sprintf("PARTIAL (%d/%d)", results, expected)
		}
		t.Logf("%-24s status %-6d results %d/%-4d %-8s [%s]",
			shape.name, status, results, expected, verdict, strings.TrimSpace(detail))
	}
}
