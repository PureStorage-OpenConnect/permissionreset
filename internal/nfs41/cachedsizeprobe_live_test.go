package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestCreateSessionCachedSizeFloor measures the smallest
// ca_maxresponsesize_cached a server will accept.
//
// It exists because a Purity//FA refuses zero with NFS4ERR_TOOSMALL, and the
// fallback in session.go had to pick a value without knowing the floor. 8 KiB was
// a guess, and MEASURED 2026-08-22 against fa-lab-01 (Purity 6.10.6) it is
// also refused -- so the guess needs replacing with this measurement.
//
// STRICTLY READ-ONLY with respect to the filesystem: it issues EXCHANGE_ID and
// CREATE_SESSION only, never a PUTFH, LOOKUP or SETATTR, and it destroys every
// session it manages to create. That matters because the FSA-lab FlashArrays host
// dozens of other engineers' filesystems. A created-then-destroyed session is
// server state rather than filesystem state, and leaving one behind would hold a
// lease, which is why the teardown is unconditional.
//
// Sequencing note: a REFUSED CREATE_SESSION creates no session and records no
// csa_sequence, so a refused attempt reuses the same value and only a success
// advances it. Getting this backwards wedges the clientid for its lease.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.200:2049 \
//	  go test ./internal/nfs41/ -run TestCreateSessionCachedSizeFloor -v
func TestCreateSessionCachedSizeFloor(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	if server == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER (host:2049) to run the cached-size floor probe")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
	if err != nil {
		t.Fatalf("dial %s: %v", server, err)
	}
	defer conn.Close()

	owner := []byte(fmt.Sprintf("permissionreset-cachedsizeprobe-%x", processClientVerifier))
	reg, err := ExchangeID(ctx, conn, owner)
	if err != nil {
		t.Fatalf("EXCHANGE_ID: %v", err)
	}
	t.Logf("server_owner=%q impl_name=%q", reg.Identity().Owner, reg.Identity().ImplName)

	machine := string(reg.owner)
	if len(machine) > maxAuthSysMachineName {
		machine = machine[:maxAuthSysMachineName]
	}
	sec := xdr.Callback_sec_parms4{Cb_secflavor: xdr.Uint32_t(xdr.AUTH_SYS)}
	*sec.Cbsp_sys_cred() = xdr.Authsys_parms{
		Stamp:       uint32(time.Now().Unix()),
		Machinename: machine,
	}

	sequence := reg.nextCreateSeq
	// Powers of two from zero up to the request size this client already offers.
	// A value above ca_maxresponsesize would be incoherent to ask for, so the
	// sweep stops there: if nothing in this range is accepted, the problem is not
	// the size and the probe says so rather than climbing forever.
	candidates := []uint32{0, 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10,
		128 << 10, 256 << 10, 512 << 10, requestedChannelSize}

	var accepted uint32
	var acceptedGrant xdr.Channel_attrs4
	for _, cached := range candidates {
		op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE_SESSION}
		*op.Opcreatesession() = xdr.CREATE_SESSION4args{
			Csa_clientid: reg.id,
			Csa_sequence: sequence,
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

		status, results, err := callCompound(ctx, conn, "cached-size-probe", []xdr.Nfs_argop4{op})
		if err != nil {
			t.Fatalf("cached=%d: call failed, and the sequence state is now unknown "+
				"so the probe must not continue: %v", cached, err)
		}
		if status != NFS4_OK {
			t.Logf("  cached=%-7d REFUSED status %d", cached, status)
			continue
		}

		// Success consumes the sequence, and leaves a session that must not be
		// left holding a lease on a shared array.
		sequence++
		ok := results[0].Opcreatesession().Csr_resok4()
		grant := ok.Csr_fore_chan_attrs
		t.Logf("  cached=%-7d ACCEPTED: granted cached=%d requests=%d responsesize=%d ops=%d",
			cached, grant.Ca_maxresponsesize_cached, grant.Ca_maxrequests,
			grant.Ca_maxresponsesize, grant.Ca_maxoperations)

		destroy := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
		destroy.Opdestroysession().Dsa_sessionid = ok.Csr_sessionid
		if dstatus, _, derr := callCompound(ctx, conn, "destroy", []xdr.Nfs_argop4{destroy}); derr != nil || dstatus != NFS4_OK {
			t.Errorf("cached=%d: DESTROY_SESSION status %d err %v -- a session was left "+
				"holding a lease on a shared array", cached, dstatus, derr)
		}

		if accepted == 0 && cached != 0 {
			accepted = cached
			acceptedGrant = grant
		}
		if cached == 0 {
			t.Logf("  this server accepts zero, so it is not a FlashArray-style refusal " +
				"and there is no floor to report")
			return
		}
	}

	if accepted == 0 {
		t.Fatalf("no ca_maxresponsesize_cached in %v was accepted; the refusal is not "+
			"about this value and session.go's fallback cannot fix it", candidates)
	}
	t.Logf("FLOOR: the smallest accepted ca_maxresponsesize_cached is %d. Note what the "+
		"server GRANTED in return: %d slots against the %d offered -- if that is lower, the "+
		"cache was paid for in slots, which is exactly the trade RFC 8881 section 18.36.3 "+
		"permits and the reason this client offers zero first.",
		accepted, acceptedGrant.Ca_maxrequests, defaultRequestedSlots)
}

// TestCreateSessionAttrArms finds WHICH channel attribute a server calls too
// small, after TestCreateSessionCachedSizeFloor showed it is not
// ca_maxresponsesize_cached: that probe swept 0 through 1 MiB against
// fa-lab-01 (Purity 6.10.6) and every value was refused with
// NFS4ERR_TOOSMALL, which retires the diagnosis this client shipped.
//
// Each arm changes ONE thing from the baseline this client sends, so a pass
// names the offending field rather than a working combination. The strongest
// suspect is the back channel: this client sends Csa_back_chan_attrs entirely
// zeroed because it negotiates no back channel, and a zeroed structure is
// literally a set of too-small values. Linux populates it even when it declines
// callbacks.
//
// Same discipline as the probe above: EXCHANGE_ID and CREATE_SESSION only, every
// created session destroyed, and only a success advances csa_sequence.
func TestCreateSessionAttrArms(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	if server == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER (host:2049) to run the channel-attribute arms")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
	if err != nil {
		t.Fatalf("dial %s: %v", server, err)
	}
	defer conn.Close()

	owner := []byte(fmt.Sprintf("permissionreset-attrarms-%x", processClientVerifier))
	reg, err := ExchangeID(ctx, conn, owner)
	if err != nil {
		t.Fatalf("EXCHANGE_ID: %v", err)
	}

	machine := string(reg.owner)
	if len(machine) > maxAuthSysMachineName {
		machine = machine[:maxAuthSysMachineName]
	}
	sec := xdr.Callback_sec_parms4{Cb_secflavor: xdr.Uint32_t(xdr.AUTH_SYS)}
	*sec.Cbsp_sys_cred() = xdr.Authsys_parms{
		Stamp:       uint32(time.Now().Unix()),
		Machinename: machine,
	}

	baseFore := func() xdr.Channel_attrs4 {
		return xdr.Channel_attrs4{
			Ca_maxrequestsize:         requestedChannelSize,
			Ca_maxresponsesize:        requestedChannelSize,
			Ca_maxresponsesize_cached: 0,
			Ca_maxoperations:          maxSessionOperations,
			Ca_maxrequests:            defaultRequestedSlots,
		}
	}
	// A back channel the server can believe in, for the arms that populate one.
	// ca_maxrequests 1 is what Linux offers for a callback channel it will
	// actually service; the sizes are deliberately modest because nothing will
	// ever travel on it.
	populatedBack := xdr.Channel_attrs4{
		Ca_maxrequestsize:         4 << 10,
		Ca_maxresponsesize:        4 << 10,
		Ca_maxresponsesize_cached: 0,
		Ca_maxoperations:          2,
		Ca_maxrequests:            1,
	}

	arms := []struct {
		name string
		fore xdr.Channel_attrs4
		back xdr.Channel_attrs4
	}{
		{"baseline (what this client ships)", baseFore(), xdr.Channel_attrs4{}},
		{"back channel populated", baseFore(), populatedBack},
		{"back channel populated, cached 8K", func() xdr.Channel_attrs4 {
			f := baseFore()
			f.Ca_maxresponsesize_cached = 8 << 10
			return f
		}(), populatedBack},
		{"fore sizes 64K", func() xdr.Channel_attrs4 {
			f := baseFore()
			f.Ca_maxrequestsize, f.Ca_maxresponsesize = 64<<10, 64<<10
			return f
		}(), xdr.Channel_attrs4{}},
		{"fore sizes 4M", func() xdr.Channel_attrs4 {
			f := baseFore()
			f.Ca_maxrequestsize, f.Ca_maxresponsesize = 4<<20, 4<<20
			return f
		}(), xdr.Channel_attrs4{}},
		{"one slot", func() xdr.Channel_attrs4 {
			f := baseFore()
			f.Ca_maxrequests = 1
			return f
		}(), xdr.Channel_attrs4{}},
		{"maxoperations 2", func() xdr.Channel_attrs4 {
			f := baseFore()
			f.Ca_maxoperations = 2
			return f
		}(), xdr.Channel_attrs4{}},
	}

	sequence := reg.nextCreateSeq
	for _, arm := range arms {
		op := xdr.Nfs_argop4{Argop: xdr.OP_CREATE_SESSION}
		*op.Opcreatesession() = xdr.CREATE_SESSION4args{
			Csa_clientid:        reg.id,
			Csa_sequence:        sequence,
			Csa_fore_chan_attrs: arm.fore,
			Csa_back_chan_attrs: arm.back,
			Csa_sec_parms:       []xdr.Callback_sec_parms4{sec},
		}
		status, results, err := callCompound(ctx, conn, "attr-arms", []xdr.Nfs_argop4{op})
		if err != nil {
			t.Fatalf("%s: call failed, sequence state now unknown: %v", arm.name, err)
		}
		if status != NFS4_OK {
			t.Logf("  %-38s REFUSED status %d", arm.name, status)
			continue
		}
		sequence++
		ok := results[0].Opcreatesession().Csr_resok4()
		g := ok.Csr_fore_chan_attrs
		t.Logf("  %-38s ACCEPTED: granted requests=%d responsesize=%d ops=%d cached=%d",
			arm.name, g.Ca_maxrequests, g.Ca_maxresponsesize, g.Ca_maxoperations,
			g.Ca_maxresponsesize_cached)

		destroy := xdr.Nfs_argop4{Argop: xdr.OP_DESTROY_SESSION}
		destroy.Opdestroysession().Dsa_sessionid = ok.Csr_sessionid
		if ds, _, derr := callCompound(ctx, conn, "destroy", []xdr.Nfs_argop4{destroy}); derr != nil || ds != NFS4_OK {
			t.Errorf("%s: DESTROY_SESSION status %d err %v -- a session was left holding "+
				"a lease on a shared array", arm.name, ds, derr)
		}
	}
}
