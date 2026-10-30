package nfs41

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
)

// TestClientIDTrunkingProbe diagnoses Defect 3: the connection pool cannot open
// a second session, and `--connections >= 2` fails at startup with
//
//	nfs41: open pool connection 2: nfs41: CREATE_SESSION status NFS4ERR_INVAL (22)
//
// Two hypotheses were open. Either the array refuses more than one session per
// client ID, or the client's CREATE_SESSION is malformed on the second
// connection. RFC 8881 section 2.10.5 argues for the second: a server that
// supports session trunking for a network address MUST support client ID
// trunking for that same address, and this array plainly supports session
// trunking -- the kernel mounts it nconnect=16 every day. The same section
// describes how a client establishes client ID trunking: it invokes EXCHANGE_ID
// on EACH connection with the same client owner, checks that the returned
// client ID and server scope match, and only then sends CREATE_SESSION on that
// connection. The pool does one EXCHANGE_ID on connection one and then sends
// CREATE_SESSION on a connection the server's state layer has never seen.
//
// MEASURED 2026-08-21 against an S200 on Purity 4.8.0 (198.51.100.54). That
// reasoning is wrong, and the four arms below are what disproved it:
//
//   - A: one EXCHANGE_ID, CREATE_SESSION on a second connection -> NFS4ERR_INVAL.
//     Reproduces the CLI failure in-package.
//   - B: EXCHANGE_ID per connection with the same owner and verifier returns the
//     SAME client ID -- so the array does advertise client ID trunking -- and then
//     refuses the second CREATE_SESSION anyway.
//   - C: both CREATE_SESSIONs down the SAME connection, which the server has
//     already accepted a session on -> also NFS4ERR_INVAL. The connection is
//     irrelevant.
//   - D: 16 connections, each with its OWN client owner and therefore its own
//     client ID -> 16 usable sessions, 2048 slots.
//
// Conclusion: this array permits exactly ONE session per client ID, which
// contradicts the MUST in section 2.10.5, since it supports session trunking on
// the same address (the kernel mounts it nconnect=16). csa_sequence is exonerated
// -- arm B sent 1 and arms A and C sent 2, and all three were refused with INVAL
// rather than the NFS4ERR_SEQ_MISORDERED that section 18.36.4 specifies for a
// sequencing fault. The attribute-based INVAL causes in section 18.36.3 are
// excluded because the first CREATE_SESSION on each arm sends byte-identical
// attributes and succeeds.
//
// So the pool cannot share a client ID. It needs N independent clients, one per
// connection, which is what arm D validates at the CLI's default width.
//
// The attribute-based causes of NFS4ERR_INVAL in section 18.36.3 are excluded
// by construction, because both arms send identical channel attributes on both
// connections and the first connection succeeds in both arms.
//
// The client owner is the discriminator, so it must be identical across the two
// connections in arm B and the process-wide co_verifier must be reused. A fresh
// verifier under the same owner is a new client incarnation and would destroy
// arm B's first session rather than trunk with it.
//
// It touches no production code.
//
//	PERMISSIONRESET_TEST_SERVER=198.51.100.54:2049 \
//	  go test ./internal/nfs41/ -run TestClientIDTrunkingProbe -v
func TestClientIDTrunkingProbe(t *testing.T) {
	server := os.Getenv("PERMISSIONRESET_TEST_SERVER")
	if server == "" {
		t.Skip("set PERMISSIONRESET_TEST_SERVER (host:2049) to run the trunking probe")
	}

	t.Run("ArmA_oneExchangeID_twoConnections", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		owner := []byte(fmt.Sprintf("permissionreset-trunkprobe-A-%x", processClientVerifier))

		conn1, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
		if err != nil {
			t.Fatalf("dial 1: %v", err)
		}
		defer conn1.Close()

		reg, err := ExchangeID(ctx, conn1, owner)
		if err != nil {
			t.Fatalf("EXCHANGE_ID on connection 1: %v", err)
		}
		t.Logf("connection 1: EXCHANGE_ID -> clientid=%#x scope=%q", reg.ID(), reg.Identity().Scope)

		s1, err := NewSession(ctx, conn1, reg, 0, nil)
		if err != nil {
			t.Fatalf("session on connection 1: %v", err)
		}
		defer func() { _ = s1.Destroy(context.Background()) }()
		t.Logf("connection 1: CREATE_SESSION OK, %d slots", s1.Slots())

		conn2, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
		if err != nil {
			t.Fatalf("dial 2: %v", err)
		}
		defer conn2.Close()

		// This is the call the pool makes and the one that fails. Reusing reg
		// means connection 2 sends CREATE_SESSION for a client ID that was
		// established on a different connection.
		s2, err := NewSession(ctx, conn2, reg, 0, nil)
		if err != nil {
			t.Logf("REPRODUCED: reusing one registration on a second connection fails: %v", err)
			return
		}
		defer func() { _ = s2.Destroy(context.Background()) }()
		t.Errorf("NOT REPRODUCED: a second session on one registration succeeded (%d slots). "+
			"Defect 3 is not what STATUS.md says it is; re-diagnose before changing the pool.", s2.Slots())
	})

	t.Run("ArmB_exchangeIDPerConnection_sameOwner", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		owner := []byte(fmt.Sprintf("permissionreset-trunkprobe-B-%x", processClientVerifier))

		conn1, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
		if err != nil {
			t.Fatalf("dial 1: %v", err)
		}
		defer conn1.Close()

		reg1, err := ExchangeID(ctx, conn1, owner)
		if err != nil {
			t.Fatalf("EXCHANGE_ID on connection 1: %v", err)
		}
		s1, err := NewSession(ctx, conn1, reg1, 0, nil)
		if err != nil {
			t.Fatalf("session on connection 1: %v", err)
		}
		defer func() { _ = s1.Destroy(context.Background()) }()
		t.Logf("connection 1: clientid=%#x, %d slots", reg1.ID(), s1.Slots())

		conn2, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
		if err != nil {
			t.Fatalf("dial 2: %v", err)
		}
		defer conn2.Close()

		// Same owner, same process-wide verifier, so RFC 8881 section 18.35
		// requires the same client ID back. If it differs, this is not client ID
		// trunking and the whole approach is wrong.
		reg2, err := ExchangeID(ctx, conn2, owner)
		if err != nil {
			t.Fatalf("EXCHANGE_ID on connection 2: %v", err)
		}
		t.Logf("connection 2: clientid=%#x scope=%q eir_sequenceid=%d (connection 1 had %d, "+
			"advanced to %d by its own CREATE_SESSION)",
			reg2.ID(), reg2.Identity().Scope, reg2.nextCreateSeq, reg2.nextCreateSeq, reg1.nextCreateSeq)

		if reg2.ID() != reg1.ID() {
			t.Errorf("client IDs differ across connections (%#x vs %#x); the same owner and "+
				"verifier must yield one client ID, so this array does not do client ID "+
				"trunking at all and the pool needs independent clients instead",
				reg1.ID(), reg2.ID())
		}
		if reg2.Identity().Scope != reg1.Identity().Scope {
			t.Errorf("server scope differs across connections (%q vs %q); RFC 8881 section "+
				"2.10.5 forbids trunking across differing scopes",
				reg1.Identity().Scope, reg2.Identity().Scope)
		}

		// MEASURED: this still fails. Re-identifying on the connection was the
		// leading hypothesis and it is wrong -- the array hands back the same
		// client ID, confirming it advertises client ID trunking, and then refuses
		// the second CREATE_SESSION anyway. Arm C shows why: the limit is one
		// session per client ID, so no amount of per-connection handshaking helps.
		//
		// Kept as an arm rather than deleted, because a firmware that starts
		// honouring RFC 8881 section 2.10.5 would show up here first, and because
		// it is the only place the same-client-ID-across-connections fact is
		// recorded.
		s2, err := NewSession(ctx, conn2, reg2, 0, nil)
		if err != nil {
			t.Logf("EXPECTED FAILURE: EXCHANGE_ID per connection returns the same client ID "+
				"but CREATE_SESSION on connection 2 is still refused: %v", err)
			return
		}
		defer func() { _ = s2.Destroy(context.Background()) }()
		t.Logf("BEHAVIOUR CHANGE: this array now accepts a second session per client ID "+
			"(%d slots). Client ID trunking is available; the independent-clients pool can "+
			"be simplified back to one client ID.", s2.Slots())

		// Both sessions must be independently usable, not merely created. A
		// server that accepted the second CREATE_SESSION and then refused traffic
		// on it would look like a fix and behave like the defect.
		for i, s := range []*Session{s1, s2} {
			status, results, err := s.Do(ctx, []xdr.Nfs_argop4{OpPutRootFH(), OpGetFH()})
			switch {
			case err != nil:
				t.Errorf("session %d created but unusable: %v", i+1, err)
			case status != NFS4_OK:
				t.Errorf("session %d created but PUTROOTFH+GETFH returned status %d", i+1, status)
			default:
				t.Logf("session %d usable: %d results", i+1, len(results))
			}
		}
	})

	// Arm C decides whether the CONNECTION matters at all. Both earlier arms put
	// the second CREATE_SESSION on a second connection, so "the server has never
	// seen this connection" and "the server refuses a second session on this
	// client ID" are still confounded. This arm sends both CREATE_SESSIONs down
	// the SAME connection, which the server has already accepted a session on.
	//
	// Succeeds -> the client ID tolerates two sessions and the connection is the
	// problem. Fails -> the array allows exactly one session per client ID,
	// regardless of connection, and the pool's premise is dead.
	t.Run("ArmC_twoSessionsOneConnection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		owner := []byte(fmt.Sprintf("permissionreset-trunkprobe-C-%x", processClientVerifier))

		conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		reg, err := ExchangeID(ctx, conn, owner)
		if err != nil {
			t.Fatalf("EXCHANGE_ID: %v", err)
		}
		t.Logf("clientid=%#x, eir_sequenceid=%d", reg.ID(), reg.nextCreateSeq)

		s1, err := NewSession(ctx, conn, reg, 0, nil)
		if err != nil {
			t.Fatalf("first session: %v", err)
		}
		defer func() { _ = s1.Destroy(context.Background()) }()
		t.Logf("session 1 OK (%d slots); csa_sequence for the next call is now %d",
			s1.Slots(), reg.nextCreateSeq)

		s2, err := NewSession(ctx, conn, reg, 0, nil)
		if err != nil {
			t.Logf("RESULT: one session per client ID. A second CREATE_SESSION on the SAME "+
				"connection also fails: %v. The connection is irrelevant; the pool cannot "+
				"share a client ID across sessions on this array.", err)
			return
		}
		defer func() { _ = s2.Destroy(context.Background()) }()
		t.Logf("RESULT: two sessions on one client ID succeed when both CREATE_SESSIONs go "+
			"down the SAME connection (%d slots). The defect is connection binding, not a "+
			"per-client-ID session limit.", s2.Slots())
	})

	// Arm D validates the only remaining design at the width the CLI actually
	// defaults to. Arms A-C establish that one client ID carries exactly one
	// session, so a pool of N connections needs N INDEPENDENT client IDs -- a
	// distinct client owner per connection, not a shared one. Three separate
	// processes were already observed to work; this proves it inside one process
	// at --connections 16, and that all 16 sessions are usable rather than merely
	// created.
	t.Run("ArmD_sixteenIndependentClients", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		const want = 16
		ids := make(map[uint64]int, want)
		for i := 0; i < want; i++ {
			conn, err := NewConn(ctx, TCPDialer(server), CurrentAuthSys())
			if err != nil {
				t.Fatalf("dial %d: %v", i+1, err)
			}
			defer conn.Close()

			// A distinct owner per connection is what makes these independent
			// clients. Reusing one owner would collapse them onto a single client
			// ID and reproduce arm C.
			owner := []byte(fmt.Sprintf("permissionreset-trunkprobe-D-%x-%d", processClientVerifier, i))
			reg, err := ExchangeID(ctx, conn, owner)
			if err != nil {
				t.Fatalf("EXCHANGE_ID %d: %v", i+1, err)
			}
			s, err := NewSession(ctx, conn, reg, 0, nil)
			if err != nil {
				t.Fatalf("session %d of %d: %v", i+1, want, err)
			}
			defer func() { _ = s.Destroy(context.Background()) }()

			status, _, err := s.Do(ctx, []xdr.Nfs_argop4{OpPutRootFH(), OpGetFH()})
			if err != nil || status != NFS4_OK {
				t.Fatalf("session %d created but unusable: status=%d err=%v", i+1, status, err)
			}
			ids[reg.ID()] = s.Slots()
		}

		if len(ids) != want {
			t.Errorf("%d distinct client IDs for %d connections; a collision means the owners "+
				"are not distinct", len(ids), want)
		}
		total := 0
		for _, slots := range ids {
			total += slots
		}
		t.Logf("RESULT: %d independent clients, each with one usable session, %d slots total. "+
			"This is the shape the pool must be built in.", len(ids), total)
	})
}
