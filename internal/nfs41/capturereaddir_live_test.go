package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestCaptureReadDirReply writes one real COMPOUND reply body to a file, for use
// as golden input to the decoder benchmarks and the differential decode test.
//
// It exists so those tests run against bytes a FlashBlade actually sent. The
// alternative — marshalling a COMPOUND4res with the vendored encoder and feeding
// it back to the decoders — tests the two decoders against each other but not
// against reality, and would quietly bless any shared misreading of the RFC. It
// is also how a plausible-looking file of invented bytes ends up in testdata,
// which this repository does not do.
//
// The reply is written verbatim: the RPC layer has already stripped the record
// mark and the RPC header, so what lands on disk is the COMPOUND4res body that
// ParseCompound takes as its argument.
//
// Read-only: PUTFH on a directory the caller names, then READDIR.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.54:2049 \
//	PERMISSIONRESET_TEST_EXPORT=/bench-perms \
//	PERMISSIONRESET_CAPTURE_DIR=/bench-perms/bench-s200 \
//	PERMISSIONRESET_CAPTURE_OUT=/tmp/readdir_reply.bin \
//	  go test ./internal/nfs41/ -run TestCaptureReadDirReply -v
func TestCaptureReadDirReply(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	export := os.Getenv("PERMISSIONRESET_TEST_EXPORT")
	dir := os.Getenv("PERMISSIONRESET_CAPTURE_DIR")
	out := os.Getenv("PERMISSIONRESET_CAPTURE_OUT")
	if server == "" || export == "" || dir == "" || out == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER, PERMISSIONRESET_TEST_EXPORT, PERMISSIONRESET_CAPTURE_DIR and PERMISSIONRESET_CAPTURE_OUT")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cl, err := New(ctx, Config{
		Server:      server,
		Export:      export,
		Target:      dir,
		Connections: 1,
		RPCTimeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("client for %s: %v", dir, err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}

	entry, err := cl.pickEntry()
	if err != nil {
		t.Fatalf("pick a pool entry: %v", err)
	}

	// Ask for the same four attributes per entry that ReadDir asks for, so the
	// captured reply has the shape the hot path actually decodes.
	maxcount := min(entry.session.ChannelAttrs().MaxResponseSize-readdirCompoundOverhead, uint32(64<<10))
	ops := []xdr.Nfs_argop4{
		OpPutFH(root.FH),
		OpReadDir(0, [8]byte{}, maxcount, maxcount,
			fattr4Type, fattr4Mode, fattr4Filehandle, fattr4FSID),
	}

	request, err := BuildCompound("capture-readdir", ops)
	if err != nil {
		t.Fatalf("build COMPOUND: %v", err)
	}
	// The session's SEQUENCE is deliberately absent: this is the raw two-op
	// COMPOUND, so the capture holds no session identifier and no slot state,
	// which makes it safe to commit and reusable forever.
	reply, err := entry.conn.Call(ctx, nfsProgram, nfsProgramVersion, nfsProcCompound, request)
	if err != nil {
		t.Fatalf("READDIR call: %v", err)
	}

	status, results, err := ParseCompound(reply)
	if err != nil {
		t.Fatalf("the captured reply does not parse, so do not keep it: %v", err)
	}
	if status != NFS4_OK {
		t.Fatalf("READDIR COMPOUND status %d; capture only successful replies", status)
	}
	if len(results) != 2 || results[1].Resop != xdr.OP_READDIR {
		t.Fatalf("expected PUTFH+READDIR results, got %d", len(results))
	}

	page, err := readDirResult(append([]xdr.Nfs_resop4{{}}, results...), dir)
	if err != nil {
		t.Fatalf("decode the captured page: %v", err)
	}

	if err := os.WriteFile(out, reply, 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("wrote %s: %d bytes, %d raw entries, %d usable, eof=%v",
		out, len(reply), page.raw, len(page.entries), page.eof)
	t.Logf("provenance line for testdata/README.md: %s",
		fmt.Sprintf("COMPOUND reply to PUTFH+READDIR, %d bytes, %d entries, captured from %s %s",
			len(reply), page.raw, server, dir))
}
