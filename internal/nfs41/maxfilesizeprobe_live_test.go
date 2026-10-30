package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestMaxFileSizeProbe reads FATTR4_MAXFILESIZE off a server and reports it
// against the gate's table, without going through the gate.
//
// This answers the last open question in STATUS.md and HANDOFF.md: the
// Purity//FA 6.6.10+ max-file-size byte value. FA File release notes say the
// limit rose to "4 PB" (PURE-316110, PURE-322426) but do not give the byte
// value, and 2^52 and 4e15 are both plausible readings of "4 PB". The design
// doc's instruction is explicit — measure it against a real array rather than
// guessing it into pureMaxFileSizes — because the gate is one exact-match test
// and a wrong constant either refuses every FlashArray or accepts something that
// is not one.
//
// It cannot use nfs41.New: New IS the gate, so on an unlisted value it returns
// ErrNotPureServer and never tells the caller what it saw. The escape hatch flag
// would get past that, but only by logging the number as a side effect of a call
// whose purpose is something else. A probe that reports the measurement as its
// result is the honest shape.
//
// STRICTLY READ-ONLY, and deliberately so. The FlashArray this was written
// against hosts dozens of other engineers' filesystems, so the probe issues
// PUTROOTFH and GETATTR against the pseudo-root and nothing else: no LOOKUP into
// anyone's export, no filesystem or export created, nothing written. The
// pseudo-root's max file size is the server's answer for the whole namespace,
// which is exactly what the gate reads.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.200:2049 \
//	  go test ./internal/nfs41/ -run TestMaxFileSizeProbe -v
func TestMaxFileSizeProbe(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	if server == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER (host:2049) to run the max-file-size probe")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
	if err != nil {
		t.Fatalf("dial %s: %v", server, err)
	}
	defer conn.Close()

	owner := []byte(fmt.Sprintf("permissionreset-maxfilesizeprobe-%x", processClientVerifier))
	reg, err := ExchangeID(ctx, conn, owner)
	if err != nil {
		t.Fatalf("EXCHANGE_ID: %v", err)
	}
	identity := reg.Identity()
	t.Logf("EXCHANGE_ID: server_owner=%q server_scope=%q impl_name=%q impl_domain=%q",
		identity.Owner, identity.Scope, identity.ImplName, identity.ImplDomain)

	session, err := NewSession(ctx, conn, reg, 0, func(msg string) { t.Log(msg) })
	if err != nil {
		t.Fatalf("CREATE_SESSION: %v", err)
	}
	defer func() {
		if err := session.Destroy(context.Background()); err != nil {
			t.Logf("warning: DESTROY_SESSION failed, session leaks until lease expiry: %v", err)
		}
	}()

	attrs := session.ChannelAttrs()
	t.Logf("granted fore-channel: maxrequests=%d maxresponsesize=%d maxoperations=%d",
		attrs.MaxRequests, attrs.MaxResponseSize, attrs.MaxOperations)

	status, results, err := session.Do(ctx, []xdr.Nfs_argop4{
		OpPutRootFH(),
		OpGetAttr(fattr4MaxFileSize),
	})
	if err != nil {
		t.Fatalf("PUTROOTFH+GETATTR: %v", err)
	}
	if status != NFS4_OK {
		t.Fatalf("PUTROOTFH+GETATTR status %d", status)
	}
	// Session.Do prepends SEQUENCE, so the results are SEQUENCE, PUTROOTFH,
	// GETATTR. This used to index results[1] and expect two results, which was
	// never exercised: every FlashArray run died at CREATE_SESSION before reaching
	// this line, and the FlashBlade path reads the attribute elsewhere. Found the
	// moment the back-channel fix let a session open.
	if len(results) != 3 || results[2].Resop != xdr.OP_GETATTR {
		t.Fatalf("expected SEQUENCE+PUTROOTFH+GETATTR, got %d results", len(results))
	}

	decoded, err := getAttrResult(results[2])
	if err != nil {
		t.Fatalf("decode GETATTR: %v", err)
	}
	maxFileSize, err := decodeUint64Attribute(decoded, fattr4MaxFileSize)
	if err != nil {
		t.Fatalf("decode FATTR4_MAXFILESIZE: %v", err)
	}

	t.Logf("RESULT: FATTR4_MAXFILESIZE = %d", maxFileSize)
	for _, candidate := range []struct {
		label string
		value uint64
	}{
		{"2^46 (64 TiB, the value the gate accepts today)", 1 << 46},
		{"2^52 (4 PiB)", 1 << 52},
		{"4e15 (4 PB decimal)", 4_000_000_000_000_000},
		{"2^53", 1 << 53},
	} {
		if maxFileSize == candidate.value {
			t.Logf("  matches %s exactly", candidate.label)
		}
	}
	if description, known := pureMaxFileSizes[maxFileSize]; known {
		t.Logf("  the gate ALREADY accepts this value: %s", description)
	} else {
		t.Logf("  the gate REFUSES this value today. Adding it to pureMaxFileSizes is what " +
			"would let this platform use --transport=userspace, and this measurement is the " +
			"evidence the design doc asks for before doing so. One array on one release is " +
			"still one data point: the 2^46 entry is trusted because two models and two " +
			"Purity families reported it.")
	}
}
