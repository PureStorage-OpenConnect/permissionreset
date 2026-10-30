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

// TestReadDirBundleTiming measures whether bundling several READDIRs into one
// COMPOUND is worth anything, by fully enumerating the same set of directories
// at several bundle widths and comparing wall time and COMPOUND count.
//
// Why this is a separate probe from TestBundleBounds: that one answered whether
// the shape is LEGAL (it is -- seven READDIRs in one COMPOUND were accepted on
// both arrays, and READDIR is not under FlashBlade's GETATTR cap of 4). Legal is
// not the same as useful, and the plan ranked multi-READDIR as the weaker play
// for a specific reason worth testing rather than assuming:
//
//	N READDIRs in one COMPOUND share the single ca_maxresponsesize, so each
//	member's rd_maxcount falls to roughly budget/N. On large directories that
//	buys extra READDIR rounds back, and the saving in COMPOUNDs is spent again
//	on continuations.
//
// So the arms below divide the maxcount budget by the bundle width, exactly as a
// real implementation would have to, and enumerate to eof -- counting the
// continuations rather than stopping at the first page. An arm that needs N times
// the rounds to send N times fewer COMPOUNDs has bought nothing, and this is the
// shape of measurement that can tell the difference.
//
// The result is a property of the directory-size distribution as much as of the
// server. Log the distribution alongside the timings: a tree of three-entry
// directories and a tree of ten-thousand-entry directories will not agree, and a
// number quoted without the distribution it came from is not portable to another
// tree. See the sizes histogram in the output.
//
// Connections is pinned to 1 so this measures per-RPC cost rather than how well
// the client parallelises. The walk's real concurrency is a separate question.
//
// Read-only: READDIR only. Nothing here mutates.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.54:2049 \
//	PERMISSIONRESET_TEST_EXPORT=/bench-perms \
//	PERMISSIONRESET_TRAVERSE_DIR=/bench-perms/bench-s200 \
//	  ./nfs41.test -test.run TestReadDirBundleTiming -test.v -test.timeout 30m
func TestReadDirBundleTiming(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_TRAVERSE_DIR")
	if server == "" || export == "" || dir == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT and PERMISSIONRESET_TRAVERSE_DIR")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	cl, err := New(ctx, Config{Server: server, Export: export, Target: dir,
		Connections: 1, RPCTimeout: 60 * time.Second,
		AllowNonPureServer: allowNonPureServer()})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Collect a working set of directories by breadth-first descent, using the
	// production ReadDir so gathering the set costs nothing this probe measures.
	// A fixed count rather than the whole tree: 135k directories at four arms is
	// hours, and the comparison only needs the arms to see the same set.
	want := 3000
	if v := os.Getenv("PERMISSIONRESET_READDIR_DIRS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &want); err != nil {
			t.Fatalf("PERMISSIONRESET_READDIR_DIRS: %v", err)
		}
	}
	type dirRef struct {
		path string
		fh   []byte
		size int
	}
	var set []dirRef
	queue := []transport.Ref{root}
	for len(queue) > 0 && len(set) < want {
		cur := queue[0]
		queue = queue[1:]
		entries, err := cl.ReadDir(cur)
		if err != nil {
			t.Fatalf("gather %s: %v", cur.Path, err)
		}
		for _, e := range entries {
			if !e.IsDir || e.IsSymlink || len(e.Ref.FH) == 0 {
				continue
			}
			ref := transport.Ref{Path: cur.Path + "/" + e.Name, FH: e.Ref.FH}
			queue = append(queue, ref)
			if len(set) < want {
				set = append(set, dirRef{ref.Path, ref.FH, 0})
			}
		}
	}
	if len(set) < 8 {
		t.Fatalf("found only %d directories below %s; need at least 8", len(set), dir)
	}

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	session := entry.session
	attrs := session.ChannelAttrs()
	budget := attrs.MaxResponseSize - readdirCompoundOverhead
	t.Logf("negotiated channel: maxoperations=%d maxresponsesize=%d (readdir budget %d)",
		attrs.MaxOperations, attrs.MaxResponseSize, budget)
	t.Logf("working set: %d directories below %s", len(set), dir)

	// debugRounds dumps the first N COMPOUNDs of each arm result-by-result. The
	// entry counts diverging between widths is either our decoder mishandling a
	// multi-READDIR reply or the server truncating one, and those lead to
	// opposite conclusions -- so the per-result statuses have to be visible.
	debugRounds := 0
	if v := os.Getenv("PERMISSIONRESET_READDIR_DEBUG"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &debugRounds); err != nil {
			t.Fatalf("PERMISSIONRESET_READDIR_DEBUG: %v", err)
		}
	}

	// send issues one COMPOUND and returns the per-member READDIR results in
	// order. Slot accounting follows TestBundleBounds: RFC 8881 section 2.203.0.113.2
	// says an error from SEQUENCE leaves the sequence ID unspent, so a COMPOUND
	// refused AT SEQUENCE must be reclaimed rather than released. Releasing it
	// desyncs the slot and every later call earns NFS4ERR_SEQ_MISORDERED.
	send := func(ops []xdr.Nfs_argop4) (status uint32, res []xdr.Nfs_resop4, err error) {
		session.stateMu.RLock()
		id := session.id
		table := session.slots
		session.stateMu.RUnlock()

		sl, acqErr := table.acquire(ctx)
		if acqErr != nil {
			return 0, nil, fmt.Errorf("acquire: %w", acqErr)
		}
		compound := make([]xdr.Nfs_argop4, 1, len(ops)+1)
		compound[0] = OpSequence(id, sl.seqID, sl.id, uint32(table.size()-1))
		compound = append(compound, ops...)
		request, buildErr := BuildCompound("readdirbundle", compound)
		if buildErr != nil {
			table.reclaim(sl)
			return 0, nil, fmt.Errorf("build: %w", buildErr)
		}
		reply, callErr := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if callErr != nil {
			table.reclaim(sl)
			return 0, nil, fmt.Errorf("call: %w", callErr)
		}
		st, results, parseErr := ParseCompound(reply)
		if parseErr != nil {
			table.release(sl)
			return 0, nil, fmt.Errorf("parse: %w", parseErr)
		}
		seqFailed := len(results) > 0 && results[0].Resop == xdr.OP_SEQUENCE &&
			uint32(results[0].Opsequence().Sr_status) != 0
		if seqFailed || len(results) == 0 {
			table.reclaim(sl)
		} else {
			table.release(sl)
		}
		return uint32(st), results, nil
	}

	// enumerate runs the whole working set at bundle width n and reports what it
	// cost. Each member carries its own cookie and verifier, so a directory that
	// is not finished stays in the pending list and is picked up by a later
	// COMPOUND -- which is what makes continuations visible as extra rounds
	// rather than as silently truncated output.
	type result struct {
		width      int
		compounds  int
		rounds     int
		entries    int
		elapsed    time.Duration
		maxcount   uint32
		refusals   int
		firstError string
	}
	enumerate := func(n int) result {
		type pending struct {
			fh     []byte
			cookie uint64
			verf   [8]byte
		}
		work := make([]pending, 0, len(set))
		for _, d := range set {
			work = append(work, pending{fh: d.fh})
		}
		// Per-member share of the response budget, capped at what production asks
		// for on a single READDIR so a width of 1 reproduces today's behaviour.
		maxcount := budget / uint32(n)
		if maxcount > uint32(64<<10) {
			maxcount = uint32(64 << 10)
		}
		out := result{width: n, maxcount: maxcount}
		start := time.Now()
		for len(work) > 0 {
			batch := work
			if len(batch) > n {
				batch = batch[:n]
			}
			ops := make([]xdr.Nfs_argop4, 0, 2*len(batch))
			for _, p := range batch {
				ops = append(ops, OpPutFH(append([]byte(nil), p.fh...)))
				ops = append(ops, OpReadDir(p.cookie, p.verf, maxcount, maxcount,
					fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID))
			}
			status, results, err := send(ops)
			out.compounds++
			out.rounds++
			if debugRounds > 0 && out.rounds <= debugRounds {
				readdirs := 0
				for _, r := range results {
					if r.Resop == xdr.OP_READDIR {
						readdirs++
					}
				}
				t.Logf("  [w%d round %d] members=%d ops=%d -> status=%v results=%d readdirs=%d err=%v",
					n, out.rounds, len(batch), len(ops), xdr.Nfsstat4(status), len(results), readdirs, err)
				for i, r := range results {
					var st uint32
					switch r.Resop {
					case xdr.OP_SEQUENCE:
						st = uint32(r.Opsequence().Sr_status)
					case xdr.OP_PUTFH:
						st = uint32(r.Opputfh().Status)
					case xdr.OP_READDIR:
						st = uint32(r.Opreaddir().Status)
					}
					detail := ""
					if r.Resop == xdr.OP_READDIR && st == 0 {
						count := 0
						for e := r.Opreaddir().Resok4().Reply.Entries; e != nil; e = e.Nextentry {
							count++
						}
						detail = fmt.Sprintf(" entries=%d eof=%v", count,
							r.Opreaddir().Resok4().Reply.Eof)
					}
					t.Logf("      result %d: %v %v%s", i, r.Resop, xdr.Nfsstat4(st), detail)
				}
			}
			if err != nil {
				out.refusals++
				if out.firstError == "" {
					out.firstError = err.Error()
				}
				// Drop the batch: this arm cannot complete, and spinning on a
				// transport failure would turn a refusal into a hang.
				work = work[len(batch):]
				continue
			}
			if status != 0 && len(results) <= 1 {
				out.refusals++
				if out.firstError == "" {
					out.firstError = fmt.Sprintf("COMPOUND status %v with %d results",
						xdr.Nfsstat4(status), len(results))
				}
				work = work[len(batch):]
				continue
			}
			// Walk the results in order, pairing each READDIR with its member.
			var stillPending []pending
			member := 0
			for _, r := range results {
				if r.Resop != xdr.OP_READDIR {
					continue
				}
				if member >= len(batch) {
					break
				}
				rd := r.Opreaddir()
				if uint32(rd.Status) != 0 {
					out.refusals++
					if out.firstError == "" {
						out.firstError = fmt.Sprintf("member %d: %v", member, xdr.Nfsstat4(rd.Status))
					}
					member++
					continue
				}
				ok := rd.Resok4()
				p := batch[member]
				last := p.cookie
				for e := ok.Reply.Entries; e != nil; e = e.Nextentry {
					out.entries++
					last = uint64(e.Cookie)
				}
				if !ok.Reply.Eof {
					p.cookie = last
					copy(p.verf[:], ok.Cookieverf[:])
					stillPending = append(stillPending, p)
				}
				member++
			}
			work = append(work[len(batch):], stillPending...)
		}
		out.elapsed = time.Since(start)
		return out
	}

	widths := []int{1, 2, 4, 7}
	if v := os.Getenv("PERMISSIONRESET_READDIR_WIDTHS"); v == "2" {
		widths = []int{2}
	}
	var base result
	for _, n := range widths {
		r := enumerate(n)
		if n == 1 {
			base = r
		}
		speedup := 1.0
		if r.elapsed > 0 && base.elapsed > 0 {
			speedup = base.elapsed.Seconds() / r.elapsed.Seconds()
		}
		verdict := fmt.Sprintf("%.2fx vs width 1", speedup)
		if r.refusals > 0 {
			verdict = fmt.Sprintf("UNUSABLE: %d refusals (%s)", r.refusals, r.firstError)
		}
		t.Logf("width %d: %d COMPOUNDs, %d entries, maxcount %d, %.2fs -- %s",
			r.width, r.compounds, r.entries, r.maxcount, r.elapsed.Seconds(), verdict)
		// Entry counts must agree across arms or the arms did not do equal work
		// and the timings are not comparable. This is the check that catches a
		// maxcount split silently truncating a directory.
		if n != 1 && r.refusals == 0 && r.entries != base.entries {
			t.Errorf("width %d returned %d entries, width 1 returned %d: arms did not enumerate the same tree",
				n, r.entries, base.entries)
		}
	}
}

// TestReadDirFollowedByOp isolates whether the parse failures in
// TestReadDirBundleTiming come from bundling READDIRs or from decoding a READDIR
// result that is not the last result in the COMPOUND.
//
// TestReadDirBundleTiming showed width 1 decoding cleanly and every width >= 2
// failing with "invalid Resop", once with an opnum of 1664299826 -- which is
// ASCII, so the decoder was reading directory-entry name bytes as an operation
// number. That is the signature of consuming the wrong byte count for the READDIR
// result and desyncing into whatever follows it. If so, bundling is not the
// trigger: ANY operation after a READDIR is, and this affects the deferred
// readdir-fold (PUTFH + READDIR + SETATTR) just as much as multi-READDIR bundles.
//
// Both arms send exactly one READDIR. The only difference is whether a trivial
// GETATTR follows it.
func TestReadDirFollowedByOp(t *testing.T) {
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
	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}
	session := entry.session

	send := func(label string, ops []xdr.Nfs_argop4) {
		session.stateMu.RLock()
		id := session.id
		table := session.slots
		session.stateMu.RUnlock()
		sl, acqErr := table.acquire(ctx)
		if acqErr != nil {
			t.Fatalf("%s: acquire: %v", label, acqErr)
		}
		compound := make([]xdr.Nfs_argop4, 1, len(ops)+1)
		compound[0] = OpSequence(id, sl.seqID, sl.id, uint32(table.size()-1))
		compound = append(compound, ops...)
		request, buildErr := BuildCompound("readdirfollow", compound)
		if buildErr != nil {
			table.reclaim(sl)
			t.Fatalf("%s: build: %v", label, buildErr)
		}
		reply, callErr := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
		if callErr != nil {
			table.reclaim(sl)
			t.Fatalf("%s: call: %v", label, callErr)
		}
		st, results, parseErr := ParseCompound(reply)
		if parseErr != nil {
			table.release(sl)
			t.Errorf("%s: reply is %d bytes, server status was fine, but PARSE FAILED: %v",
				label, len(reply), parseErr)
			return
		}
		table.release(sl)
		t.Logf("%s: status=%v results=%d reply=%d bytes -- parsed OK",
			label, xdr.Nfsstat4(st), len(results), len(reply))
	}

	fh := append([]byte(nil), root.FH...)
	var verf [8]byte
	send("READDIR last", []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 65536, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	})
	send("READDIR then GETATTR", []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 65536, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpGetAttr(fattr4Mode),
	})
	send("READDIR with no attrs, then GETATTR", []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 65536, 65536),
		OpGetAttr(fattr4Mode),
	})

	// Two READDIRs on the SAME small directory. If this parses, then bundle width
	// is not the trigger and reply size is: the failing bundles asked for two
	// 64 KiB members, and a reply large enough to be split across RPC record
	// fragments would fail from its very first byte -- which is what the bundle
	// arm showed (parse failed at result 0, before SEQUENCE).
	send("two READDIRs, same small dir, 64K each", []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 65536, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 65536, 65536, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	})

	// Same shape, but each member asking for a small reply.
	send("two READDIRs, same small dir, 4K each", []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 4096, 4096, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), fh...)),
		OpReadDir(0, verf, 4096, 4096, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	})

	// The arms above all produced small replies -- the root directory holds only a
	// handful of entries, so rd_maxcount was a ceiling never approached and size
	// was never actually varied. PERMISSIONRESET_READDIR_BIGDIR names a directory large
	// enough for the reply to matter. Production caps rd_maxcount at 64 KiB, so a
	// single READDIR reply stays under that by construction; bundling two 64 KiB
	// members is the first thing in this codebase that can ask for more.
	//
	// One large single READDIR, then two of them. If the single one parses and the
	// pair does not, the ceiling is on the whole REPLY, not on the bundle width --
	// and multi-READDIR bundling is bounded by it however legal the shape is.
	big := os.Getenv("PERMISSIONRESET_READDIR_BIGDIR")
	if big == "" {
		t.Log("set PERMISSIONRESET_READDIR_BIGDIR to a large directory to test reply-size limits")
		return
	}
	bigFH, err := cl.resolvePath(ctx, big)
	if err != nil {
		t.Fatalf("resolve %s: %v", big, err)
	}
	bfh := append([]byte(nil), bigFH...)
	for _, mc := range []uint32{64 << 10, 128 << 10, 256 << 10} {
		send(fmt.Sprintf("ONE READDIR on %s, maxcount %d", big, mc), []xdr.Nfs_argop4{
			OpPutFH(append([]byte(nil), bfh...)),
			OpReadDir(0, verf, mc, mc, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		})
	}
	send(fmt.Sprintf("TWO READDIRs on %s, 64K each", big), []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	})
	send(fmt.Sprintf("FOUR READDIRs on %s, 64K each", big), []xdr.Nfs_argop4{
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
		OpPutFH(append([]byte(nil), bfh...)),
		OpReadDir(0, verf, 64<<10, 64<<10, fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	})
}
