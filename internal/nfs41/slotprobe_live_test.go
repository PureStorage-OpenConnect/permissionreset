package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestCreateSessionSlotProbe answers the open question in STATUS.md: does the
// array reduce ca_maxrequests when the client reserves reply-cache budget?
//
// session.go's create() sets Ca_maxresponsesize_cached to 0 and the comment
// there asserts that a non-zero value "invites a grant of a handful of slots in
// return", citing RFC 8881 section 18.36.3. That assertion is reasoned from the
// RFC and from what Linux does; it has never been measured against a
// FlashBlade. This probe measures it.
//
// Each arm uses its OWN connection and its OWN EXCHANGE_ID, so each gets a
// fresh clientid whose csa_sequence starts at whatever that EXCHANGE_ID
// returned. That isolation is the point: reusing one ClientRegistration across
// both arms would step nextCreateSeq out from under the create gate and wedge
// the clientid for the life of the registration.
//
// It touches no production code. Nothing here is meant to be committed.
//
//	PERMISSIONRESET_TEST_SERVER=192.0.2.50:2049 \
//	  go test ./internal/nfs41/ -run TestCreateSessionSlotProbe -v
func TestCreateSessionSlotProbe(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	if server == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER (host:2049) to run the slot probe")
	}

	arms := []struct {
		label  string
		cached xdr.Count4
	}{
		{"cached=0 (what the client ships today)", 0},
		{"cached=8MiB (the value the comment warns against)", 8 << 20},
	}

	granted := make(map[string]ChannelAttrs, len(arms))
	for _, arm := range arms {
		attrs, err := probeCreateSession(t, server, arm.cached)
		if err != nil {
			t.Fatalf("%s: %v", arm.label, err)
		}
		granted[arm.label] = attrs
		t.Logf("%-50s -> maxrequests=%3d maxresponsesize=%d maxoperations=%d",
			arm.label, attrs.MaxRequests, attrs.MaxResponseSize, attrs.MaxOperations)
	}

	base := granted[arms[0].label].MaxRequests
	withCache := granted[arms[1].label].MaxRequests
	switch {
	case withCache < base:
		t.Logf("RESULT: the array DOES trade slots for reply-cache budget "+
			"(%d slots -> %d). session.go's zero is load-bearing; keep it and keep the comment.",
			base, withCache)
	case withCache == base:
		t.Logf("RESULT: the array does NOT trade slots for reply-cache budget "+
			"(%d slots both ways). The zero is still correct — the cache buys nothing "+
			"for idempotent operations — but the comment's stated consequence does not "+
			"hold on this platform and should be softened to say so.", base)
	default:
		t.Logf("RESULT: UNEXPECTED — asking for reply cache RAISED the grant (%d -> %d). "+
			"Do not act on this without a second run.", base, withCache)
	}
}

// probeCreateSession runs one arm: dial, EXCHANGE_ID, CREATE_SESSION with the
// given ca_maxresponsesize_cached, read the grant, DESTROY_SESSION, hang up.
//
// The session is destroyed on every exit path. A leaked session holds server
// resources until its lease expires, which is rude on a shared lab array.
func probeCreateSession(t *testing.T, server string, cached xdr.Count4) (ChannelAttrs, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
	if err != nil {
		return ChannelAttrs{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	owner := []byte(fmt.Sprintf("permissionreset-slotprobe-%x-%d", processClientVerifier, cached))
	reg, err := ExchangeID(ctx, conn, owner)
	if err != nil {
		return ChannelAttrs{}, fmt.Errorf("EXCHANGE_ID: %w", err)
	}

	machine := string(owner)
	if len(machine) > maxAuthSysMachineName {
		machine = machine[:maxAuthSysMachineName]
	}
	sec := xdr.Callback_sec_parms4{Cb_secflavor: xdr.Uint32_t(xdr.AUTH_SYS)}
	*sec.Cbsp_sys_cred() = xdr.Authsys_parms{
		Stamp:       uint32(time.Now().Unix()),
		Machinename: machine,
	}

	op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE_SESSION}
	*op.Opcreatesession() = xdr.CREATE_SESSION4args{
		Csa_clientid: reg.id,
		Csa_sequence: reg.nextCreateSeq,
		Csa_fore_chan_attrs: xdr.Channel_attrs4{
			Ca_maxrequestsize:         requestedChannelSize,
			Ca_maxresponsesize:        requestedChannelSize,
			Ca_maxresponsesize_cached: cached,
			Ca_maxoperations:          maxSessionOperations,
			Ca_maxrequests:            defaultRequestedSlots,
		},
		Csa_back_chan_attrs: xdr.Channel_attrs4{},
		Csa_sec_parms:       []xdr.Callback_sec_parms4{sec},
	}

	status, results, err := callCompound(ctx, conn, "slotprobe-create-session", []xdr.Nfs_argop4{op})
	if err != nil {
		return ChannelAttrs{}, fmt.Errorf("CREATE_SESSION: %w", err)
	}
	if status != NFS4_OK {
		return ChannelAttrs{}, fmt.Errorf("CREATE_SESSION status %d", status)
	}
	if len(results) != 1 || results[0].Resop != xdr.OP_CREATE_SESSION {
		return ChannelAttrs{}, fmt.Errorf("CREATE_SESSION returned %d unexpected results", len(results))
	}
	ok := results[0].Opcreatesession().Csr_resok4()

	// Destroy before returning, including when a later check fails.
	defer func() {
		d := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
		d.Opdestroysession().Dsa_sessionid = ok.Csr_sessionid
		if _, _, err := callCompound(ctx, conn, "slotprobe-destroy-session", []xdr.Nfs_argop4{d}); err != nil {
			t.Logf("warning: DESTROY_SESSION failed, session leaks until lease expiry: %v", err)
		}
	}()

	g := ok.Csr_fore_chan_attrs
	return ChannelAttrs{
		MaxRequestSize:  uint32(g.Ca_maxrequestsize),
		MaxResponseSize: uint32(g.Ca_maxresponsesize),
		MaxOperations:   uint32(g.Ca_maxoperations),
		MaxRequests:     uint32(g.Ca_maxrequests),
	}, nil
}
